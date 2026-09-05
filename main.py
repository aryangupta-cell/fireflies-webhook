"""
Fireflies webhook receiver + transcript writer.

Flow: Fireflies POSTs to /webhook when a meeting's transcript is ready ->
verify the request is genuinely from Fireflies (HMAC-SHA256 over the raw
body, using FIREFLIES_WEBHOOK_SECRET) -> pull the full transcript via their
GraphQL API -> map it onto the drt.ta_interview_transcript schema -> insert
one row per sentence.

Offline vs online, and interviewer/candidate name extraction, both come from
one signal: the meeting TITLE. HR manually uploads the MP3 through Fireflies'
own dashboard and names it "Interviewer_Candidate_Date" (e.g.
"Priya_RahulSharma_04-09-2026"). If the title splits into >=2 "_"-separated
parts, this is treated as an offline upload (source='offline') and
interviewer_name/candidate_name/meeting_date are parsed from it. Otherwise
it's treated as a live Meet call (source='online'), same as before.

This replaces an earlier plan to tag offline uploads via client_reference_id
on a programmatic uploadAudio API call - that approach (and the URL-hosting
problem it required solving) was dropped in favor of this simpler manual
workflow. client_reference_id is no longer set by anything upstream of this
receiver, for either offline or online, so title-parsing is now the ONLY
signal distinguishing the two - there is no independent confirmation left.
A live meeting that happens to get named with two-or-more underscore-
separated words would be misclassified as an offline upload; this is an
accepted tradeoff of the simpler approach, not an oversight.

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

# Deprecated: was set as client_reference_id by a planned programmatic upload flow
# that got dropped. No longer set by anything, kept only so the field is documented
# if it ever comes back.
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


def parse_offline_title(title: str, fallback_date_string: str):
    """
    Parse the "Interviewer_Candidate_Date" naming convention HR uses when
    manually uploading an offline MP3 through Fireflies' dashboard, e.g.
    "Priya_RahulSharma_04-09-2026".

    Returns (is_offline, interviewer_name, candidate_name, meeting_date, warnings).
    is_offline is the ONLY signal used for source='offline' vs 'online' now
    (see module docstring) - a title with >=2 "_"-separated parts is treated
    as an offline upload; anything else (a real meeting title) is online.

    Never raises - a malformed/missing title just means less gets parsed,
    logged as a warning, not a crash (same graceful-degradation pattern used
    elsewhere in this file, e.g. transcript-not-found handling).
    """
    warnings = []
    title = (title or "").strip()
    parts = title.split("_") if title else []

    if len(parts) < 2:
        return False, None, None, None, warnings

    interviewer_name = parts[0].strip() or None
    candidate_name = parts[1].strip() or None
    meeting_date = None

    if len(parts) >= 3:
        date_part = parts[2].strip()
        # Example format from the convention: "04-09-2026" = DD-MM-YYYY
        for fmt in ("%d-%m-%Y", "%d-%m-%y", "%d/%m/%Y", "%Y-%m-%d"):
            try:
                meeting_date = datetime.strptime(date_part, fmt).date().isoformat()
                break
            except ValueError:
                continue
        if meeting_date is None:
            warnings.append(
                f"title date part {date_part!r} did not match any known format - "
                f"falling back to Fireflies' own dateString"
            )
    else:
        warnings.append(f"title {title!r} has no third part for date - falling back to dateString")

    if meeting_date is None:
        meeting_date = parse_meeting_date(fallback_date_string)

    return True, interviewer_name, candidate_name, meeting_date, warnings


def write_transcript_rows(transcript: dict, meeting_id: str, client_reference_id: str = None) -> dict:
    import uuid

    transcript_id = str(uuid.uuid4())
    meeting_name = transcript.get("title")
    meeting_link = transcript.get("meeting_link")
    sentences = transcript.get("sentences") or []

    # Title-parsing is the ONLY signal for offline vs online now (see module
    # docstring) - client_reference_id is deprecated and unused.
    is_offline, title_interviewer, title_candidate, title_meeting_date, title_warnings = (
        parse_offline_title(meeting_name, transcript.get("dateString"))
    )
    for w in title_warnings:
        logger.warning(f"meeting_id={meeting_id} title={meeting_name!r}: {w}")

    if is_offline:
        source = "offline"
        interviewer_name = title_interviewer
        candidate_name = title_candidate
        meeting_date = title_meeting_date
        if interviewer_name is None or candidate_name is None:
            logger.warning(
                f"meeting_id={meeting_id} title={meeting_name!r}: interviewer/candidate "
                f"came back empty after parsing - storing as NULL, needs manual follow-up"
            )
    else:
        source = "online"
        interviewer_name = None
        candidate_name = None
        meeting_date = parse_meeting_date(transcript.get("dateString"))

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
                interviewer_name,  # parsed from title for offline uploads, NULL for online (see above)
                candidate_name,
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
