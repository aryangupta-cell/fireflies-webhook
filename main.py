"""
Fireflies webhook receiver + transcript writer.

Flow: Fireflies POSTs to /webhook when a meeting's transcript is ready ->
verify the request is genuinely from Fireflies (HMAC-SHA256 over the raw
body, using FIREFLIES_WEBHOOK_SECRET) -> pull the full transcript via their
GraphQL API -> map it onto the drt.ta_interview_transcript schema -> insert
ONE row per interview (segments nested as a JSONB array), not one row per
sentence.

Offline vs online classification: meeting_link is the primary signal, NOT
title. meeting_link is only populated by Fireflies for a call on a supported
live platform (Meet, Zoom, etc) - it's null for an uploaded audio file. So:
  - meeting_link present  -> source='online', real live meeting.
  - meeting_link absent   -> source='offline', an uploaded MP3.
(Title-parsing was tried as the sole signal first, but a real Meet call
titled "Test_3" got wrongly classified offline purely because the title
happened to match the naming convention - meeting_link doesn't have that
false-positive risk, since a real meeting always gets it populated.)

Interviewer/candidate extraction now differs by source:
  - online: from `meeting_attendees` (displayName + email per participant).
    Anyone with an @axestrack.com email -> interviewer_name (first match).
    Anyone with a different domain -> candidate_name (first match). Multiple
    external participants: we pick the first and log a warning noting the
    ambiguity rather than guessing further - a real edge case (e.g. two
    candidates, or an external observer on the call) that needs a human to
    resolve, not a heuristic.
  - offline: still from the "Interviewer_Candidate_Date" title convention
    HR uses when manually uploading through Fireflies' dashboard, e.g.
    "Priya_RahulSharma_04-09-2026" (unchanged from before).

Deployed at /data/shared/Rudhi_P1/pace/transcript/ on the aterp server,
run via systemd (see fireflies-webhook.service), reverse-proxied by nginx
at https://aterp.xswift.biz/fireflies-webhook/ .

No confidence/quality signal exists for either source (Fireflies exposes
none per-sentence), so those columns were dropped entirely from the schema
rather than kept as always-NULL placeholders - see the schema migration
this file was updated alongside.
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone

import requests
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Request, HTTPException
from dotenv import load_dotenv

load_dotenv()

FIREFLIES_API_KEY = os.environ["FIREFLIES_API_KEY"]
FIREFLIES_WEBHOOK_SECRET = os.environ["FIREFLIES_WEBHOOK_SECRET"]
FIREFLIES_GRAPHQL_URL = "https://api.fireflies.ai/graphql"

INTERVIEWER_EMAIL_DOMAIN = "axestrack.com"

DB_CONFIG = {
    "host": os.environ["DB_HOST"],
    "port": os.environ["DB_PORT"],
    "dbname": os.environ["DB_NAME"],
    "user": os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("fireflies_webhook")

app = FastAPI(title="Fireflies Webhook Receiver", version="2.0.0")


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
    meeting_attendees {
      displayName
      email
    }
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
    "Priya_RahulSharma_04-09-2026". Only called for offline uploads (source
    already determined by meeting_link being absent) - this no longer
    decides source itself, just extracts names/date from the title.

    Returns (interviewer_name, candidate_name, meeting_date, warnings).
    Never raises - a malformed/missing title just means less gets parsed,
    logged as a warning, not a crash.
    """
    warnings = []
    title = (title or "").strip()
    parts = title.split("_") if title else []

    if len(parts) < 2:
        warnings.append(f"title {title!r} has fewer than 2 '_'-separated parts - interviewer/candidate left NULL")
        return None, None, parse_meeting_date(fallback_date_string), warnings

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

    return interviewer_name, candidate_name, meeting_date, warnings


def classify_online_participants(meeting_attendees: list):
    """
    For a live online meeting: classify attendees by email domain.
    @axestrack.com -> interviewer_name (first match), anything else ->
    candidate_name (first match). Multiple external participants is a real
    ambiguity (could be two candidates, or an external observer) - we pick
    the first and log a warning rather than guessing which one is "the"
    candidate.

    Returns (interviewer_name, candidate_name, warnings).
    """
    warnings = []
    interviewer_name = None
    candidate_name = None
    external_matches = []

    for attendee in meeting_attendees or []:
        email = (attendee.get("email") or "").strip()
        display_name = (attendee.get("displayName") or "").strip() or email or None
        if not email:
            continue
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if domain == INTERVIEWER_EMAIL_DOMAIN:
            if interviewer_name is None:
                interviewer_name = display_name
        else:
            external_matches.append(display_name)

    if external_matches:
        candidate_name = external_matches[0]
        if len(external_matches) > 1:
            warnings.append(
                f"multiple non-{INTERVIEWER_EMAIL_DOMAIN} participants found "
                f"({external_matches}) - picked the first as candidate_name, "
                f"needs manual confirmation"
            )

    if interviewer_name is None:
        warnings.append(f"no @{INTERVIEWER_EMAIL_DOMAIN} participant found - interviewer_name left NULL")
    if candidate_name is None:
        warnings.append("no non-interviewer-domain participant found - candidate_name left NULL")

    return interviewer_name, candidate_name, warnings


def write_transcript_row(transcript: dict, meeting_id: str) -> dict:
    import uuid

    transcript_id = str(uuid.uuid4())
    meeting_name = transcript.get("title")
    meeting_link = transcript.get("meeting_link")
    sentences = transcript.get("sentences") or []

    # meeting_link is the ONLY signal for offline vs online now (see module
    # docstring) - a real live meeting always has it populated; an uploaded
    # audio file never does.
    if meeting_link:
        source = "online"
        interviewer_name, candidate_name, warnings = classify_online_participants(
            transcript.get("meeting_attendees") or []
        )
        meeting_date = parse_meeting_date(transcript.get("dateString"))
    else:
        source = "offline"
        interviewer_name, candidate_name, meeting_date, warnings = parse_offline_title(
            meeting_name, transcript.get("dateString")
        )

    for w in warnings:
        logger.warning(f"meeting_id={meeting_id} source={source} title={meeting_name!r}: {w}")

    if not sentences:
        raise RuntimeError(f"Transcript for meeting_id={meeting_id} has no sentences")

    segments = [
        {
            "segment_start": s.get("start_time"),
            "segment_end": s.get("end_time"),
            "speaker": s.get("speaker_name") or s.get("speaker_id") or "UNKNOWN",
            "text": (s.get("text") or "").strip(),
        }
        for s in sentences
    ]

    insert_sql = """
        INSERT INTO drt.ta_interview_transcript (
            transcript_id, source, meeting_date, meeting_link, meeting_name,
            interviewer_name, candidate_name, segments
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s
        );
    """

    conn = psycopg2.connect(**DB_CONFIG, connect_timeout=10)
    try:
        cur = conn.cursor()
        cur.execute(insert_sql, (
            transcript_id,
            source,
            meeting_date,
            meeting_link,
            meeting_name,
            interviewer_name,
            candidate_name,
            psycopg2.extras.Json(segments),
        ))
        conn.commit()
        cur.close()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "transcript_id": transcript_id,
        "source": source,
        "meeting_name": meeting_name,
        "interviewer_name": interviewer_name,
        "candidate_name": candidate_name,
        "segment_count": len(segments),
    }


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

    logger.info(f"Received webhook: event={event_type!r} meeting_id={meeting_id!r}")

    if event_type != "meeting.transcribed":
        logger.info(f"Ignoring event {event_type!r} - only handling 'meeting.transcribed'")
        return {"status": "ignored", "reason": f"unhandled event: {event_type}"}

    if not meeting_id:
        logger.error("Webhook missing meeting_id")
        raise HTTPException(status_code=400, detail="Missing meeting_id")

    try:
        transcript = fetch_transcript(meeting_id)
        result = write_transcript_row(transcript, meeting_id)
        logger.info(
            f"Wrote transcript_id={result['transcript_id']} source={result['source']!r} "
            f"interviewer={result['interviewer_name']!r} candidate={result['candidate_name']!r} "
            f"segments={result['segment_count']} meeting={result['meeting_name']!r}"
        )
        return {"status": "ok", **result}
    except Exception as e:
        logger.exception(f"Failed to process meeting_id={meeting_id}")
        # Return 500 so Fireflies' webhook delivery sees a failure (may retry per their policy) -
        # swallowing this and returning 200 would silently drop a real transcript.
        raise HTTPException(status_code=500, detail=str(e))
