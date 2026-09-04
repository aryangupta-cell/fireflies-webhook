"""
Fireflies webhook receiver + transcript writer.

Flow: Fireflies POSTs to /webhook when a meeting's transcript is ready ->
verify the request is genuinely from Fireflies (HMAC-SHA256 over the raw
body, using FIREFLIES_WEBHOOK_SECRET) -> pull the full transcript via their
GraphQL API -> map it onto the drt.ta_interview_transcript schema (source='online')
-> insert one row per sentence.

Deployed at /data/shared/Rudhi_P1/pace/transcript/ on the aterp server,
run via systemd (see fireflies-webhook.service), reverse-proxied by nginx
at https://aterp.xswift.biz/fireflies-webhook/ .

avg_logprob is always NULL and needs_review always FALSE for these rows:
Fireflies' Sentence GraphQL type (checked against their published schema)
exposes no confidence/score/probability field at all, so there is nothing
to map it from - this isn't a placeholder, it's the accurate reflection of
what data exists.
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone

import requests
import psycopg2
from fastapi import FastAPI, Request, HTTPException
from dotenv import load_dotenv

load_dotenv()

FIREFLIES_API_KEY = os.environ["FIREFLIES_API_KEY"]
FIREFLIES_WEBHOOK_SECRET = os.environ["FIREFLIES_WEBHOOK_SECRET"]
FIREFLIES_GRAPHQL_URL = "https://api.fireflies.ai/graphql"

# Set as client_reference_id by the offline upload webpage when it calls Fireflies'
# uploadAudio mutation, so this receiver can tell an offline file upload apart from
# a real live Meet call (which never sets client_reference_id).
OFFLINE_UPLOAD_MARKER_PREFIX = "offline-"

DB_CONFIG = {
    "host": os.environ["DB_HOST"],
    "port": os.environ["DB_PORT"],
    "dbname": os.environ["DB_NAME"],
    "user": os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("fireflies_webhook")

app = FastAPI(title="Fireflies Webhook Receiver", version="1.0.0")


@app.get("/")
def health_check():
    return {"status": "ok", "message": "Fireflies webhook receiver is running"}


@app.head("/")
def health_check_head():
    # Render's own probe and some uptime monitors use HEAD instead of GET -
    # FastAPI doesn't auto-derive HEAD from a GET route, so this was 405ing.
    return


def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    if not signature_header:
        return False
    computed = hmac.new(
        FIREFLIES_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    # Fireflies sends the header as "sha256=<hex>" (v2 docs, confirmed) - strip the
    # prefix before comparing, or every real webhook would fail signature checks.
    received = signature_header
    if received.startswith("sha256="):
        received = received[len("sha256="):]
    # constant-time compare - avoid leaking timing info about the correct signature
    return hmac.compare_digest(computed, received)


TRANSCRIPT_QUERY = """
query Transcript($transcriptId: String!) {
  transcript(id: $transcriptId) {
    title
    meeting_link
    dateString
    sentences {
      index
      text
      raw_text
      start_time
      end_time
      speaker_id
      speaker_name
    }
  }
}
"""


def fetch_transcript(meeting_id: str) -> dict:
    resp = requests.post(
        FIREFLIES_GRAPHQL_URL,
        json={"query": TRANSCRIPT_QUERY, "variables": {"transcriptId": meeting_id}},
        headers={
            "Authorization": f"Bearer {FIREFLIES_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()
    if "errors" in payload:
        raise RuntimeError(f"Fireflies API returned errors: {payload['errors']}")
    transcript = payload.get("data", {}).get("transcript")
    if not transcript:
        raise RuntimeError(f"No transcript found for meeting_id={meeting_id}")
    return transcript


def parse_meeting_date(date_string: str):
    # dateString example: "2024-04-22T20:14:04.454Z"
    if not date_string:
        return datetime.now(timezone.utc).date().isoformat()
    try:
        return datetime.fromisoformat(date_string.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return datetime.now(timezone.utc).date().isoformat()


def write_transcript_rows(transcript: dict, meeting_id: str, client_reference_id: str = None) -> dict:
    import uuid

    transcript_id = str(uuid.uuid4())
    meeting_name = transcript.get("title")
    meeting_link = transcript.get("meeting_link")
    meeting_date = parse_meeting_date(transcript.get("dateString"))
    sentences = transcript.get("sentences") or []

    # Distinguish an offline file upload from a live Meet call: the offline upload
    # webpage sets client_reference_id to "offline-<uuid>" when it calls Fireflies'
    # uploadAudio mutation; a real live meeting never sets this, so anything without
    # that marker is a live/online meeting - matches the existing default.
    source = "offline" if (client_reference_id or "").startswith(OFFLINE_UPLOAD_MARKER_PREFIX) else "online"

    if not sentences:
        raise RuntimeError(f"Transcript for meeting_id={meeting_id} has no sentences")

    insert_sql = """
        INSERT INTO drt.ta_interview_transcript (
            transcript_id, source, meeting_date, meeting_link, meeting_name,
            interviewer_name, candidate_name, segment_start, segment_end,
            speaker, text, avg_logprob, needs_review, flag_reason,
            diarization_confidence, speaker_review_needed
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        );
    """

    conn = psycopg2.connect(**DB_CONFIG, connect_timeout=10)
    inserted = 0
    try:
        cur = conn.cursor()
        for s in sentences:
            cur.execute(insert_sql, (
                transcript_id,
                source,
                meeting_date,
                meeting_link,
                meeting_name,
                None,  # interviewer_name - Fireflies doesn't distinguish interviewer/candidate roles;
                None,  # candidate_name    speaker_name is stored in `speaker` instead, same as offline's SPEAKER_00/01 labels
                s.get("start_time"),
                s.get("end_time"),
                s.get("speaker_name") or s.get("speaker_id") or "UNKNOWN",
                (s.get("text") or "").strip(),
                None,   # avg_logprob - not available from Fireflies, see module docstring
                False,  # needs_review - no confidence signal to flag on; defaults to not-flagged
                None,   # flag_reason
                None,   # diarization_confidence - parked, out of scope (same as offline pipeline)
                False,  # speaker_review_needed - parked, out of scope
            ))
            inserted += 1
        conn.commit()
        cur.close()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {"transcript_id": transcript_id, "rows_inserted": inserted, "meeting_name": meeting_name, "source": source}


@app.post("/webhook")
async def receive_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers.get("x-hub-signature", "")

    if not verify_signature(raw_body, signature):
        logger.warning("Rejected webhook: signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    # Webhooks V2 payload shape (confirmed against Fireflies' docs):
    # {"event": "meeting.transcribed", "timestamp": ..., "meeting_id": "...", "client_reference_id": "..."}
    event_type = payload.get("event")
    meeting_id = payload.get("meeting_id")
    client_reference_id = payload.get("client_reference_id")

    logger.info(
        f"Received webhook: event={event_type!r} meeting_id={meeting_id!r} "
        f"client_reference_id={client_reference_id!r}"
    )

    if event_type != "meeting.transcribed":
        logger.info(f"Ignoring event {event_type!r} - only handling 'meeting.transcribed'")
        return {"status": "ignored", "reason": f"unhandled event: {event_type}"}

    if not meeting_id:
        logger.error("Webhook missing meeting_id")
        raise HTTPException(status_code=400, detail="Missing meeting_id")

    try:
        transcript = fetch_transcript(meeting_id)
        result = write_transcript_rows(transcript, meeting_id, client_reference_id)
        logger.info(
            f"Wrote transcript_id={result['transcript_id']} source={result['source']!r} "
            f"rows={result['rows_inserted']} meeting={result['meeting_name']!r}"
        )
        return {"status": "ok", **result}
    except Exception as e:
        logger.exception(f"Failed to process meeting_id={meeting_id}")
        # Return 500 so Fireflies' webhook delivery sees a failure (may retry per their policy) -
        # swallowing this and returning 200 would silently drop a real transcript.
        raise HTTPException(status_code=500, detail=str(e))
