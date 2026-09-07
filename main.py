"""
Fireflies webhook receiver + transcript writer.

Flow: Fireflies POSTs to /webhook when a meeting's transcript is ready ->
figure out WHICH Fireflies account it came from (see below) -> pull the full
transcript via that account's own API key -> map it onto the
drt.ta_interview_transcript schema -> insert ONE row per interview (segments
nested as a JSONB array), not one row per sentence.

Multi-account support: this receiver serves multiple HRs' individual
Fireflies accounts, all pointed at the same webhook URL. Fireflies' webhook
payload has no account/workspace/user-identifying field at all (checked
against their docs) - the only per-account thing we can configure is each
account's own webhook signing secret. So: every account gets a genuinely
UNIQUE secret when its webhook is set up on Fireflies' side, and on receipt
we try the incoming signature against every configured account's secret;
whichever one matches tells us which account's API key to use for the
GraphQL pull. FIREFLIES_ACCOUNTS (a JSON array in one env var) holds the
[{label, webhook_secret, api_key}, ...] list - adding a new HR is just
appending one entry to that array, no code change.

If two accounts were ever configured with the same secret, we could never
tell them apart (whichever is checked first always "wins"), and the failure
would be silent - a webhook would still succeed, just possibly attributed to
the wrong account. To make that impossible instead of just documented, this
module refuses to start at all if it finds a duplicate secret in
FIREFLIES_ACCOUNTS (see the check right after ACCOUNTS is loaded below).

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
    Anyone whose email domain CONTAINS "axestrack" (not exact-match - covers
    @axestrack.com, @ct.axestrack.com, @it.axestrack.com, etc) is a candidate
    interviewer, UNLESS their email is in the HR-exclusion Google Sheet (HR
    often opens/closes the call but isn't "the interviewer" for this row).
    After HR exclusion: 0 remaining internal participants -> interviewer_name
    NULL; exactly 1 -> that person's displayName; 2+ -> comma-separated
    displayNames (e.g. "Priya, Rahul") - genuinely ambiguous which one is
    "the" interviewer when more than one remains, so all of them are kept
    rather than arbitrarily picking one. Anyone with a non-axestrack domain
    -> candidate_name (first match; multiple such participants still log a
    warning and pick the first, same as before).
  - offline: still from the "Interviewer_Candidate_Date[_Time]" title
    convention HR uses when manually uploading through Fireflies' dashboard,
    e.g. "Priya_RahulSharma_04-09-2026" or, if a start time is included,
    "Priya_RahulSharma_04-09-2026_14-32" (HH-MM, 24h, dash not colon since
    colons aren't valid in Windows filenames).

HR exclusion list: fetched live from a Google Sheet (gspread, same service-
account pattern as emp_details_hrt.py elsewhere in this org's codebase) on
every request - not cached/baked in, so editing the sheet takes effect
immediately with no redeploy. GOOGLE_SHEET_ID (env var) points at it;
GOOGLE_SERVICE_ACCOUNT_JSON (env var, the full key file contents as a JSON
string) authenticates, since Render has no access to a local key file.

Segment timestamps: converted from elapsed-seconds-into-the-recording to
real wall-clock time ("HH:MM:SS", Asia/Kolkata) wherever a reliable meeting
start time exists - online: Fireflies' own dateString (see caveat below);
offline: parsed from the title's optional 4th "_"-separated part. If no
valid start time can be determined for either source, segment_start/
segment_end are left NULL rather than guessing - same principle as the date
fields. NOTE: Fireflies' docs do not explicitly document dateString as the
meeting's actual start time (vs. "when the transcript record was created") -
this is a reasonable but unverified assumption for online meetings.

Deployed at /data/shared/Rudhi_P1/pace/transcript/ on the aterp server,
run via systemd (see fireflies-webhook.service), reverse-proxied by nginx
at https://aterp.xswift.biz/fireflies-webhook/ .

No confidence/quality signal exists for either source (Fireflies exposes
none per-sentence), so those columns were dropped entirely from the schema
rather than kept as always-NULL placeholders - see the schema migration
this file was updated alongside.
"""

import os
import json
import re
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone

import pytz
import gspread
import requests
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Request, HTTPException
from dotenv import load_dotenv

load_dotenv()

IST = pytz.timezone("Asia/Kolkata")

FIREFLIES_GRAPHQL_URL = "https://api.fireflies.ai/graphql"
INTERVIEWER_EMAIL_DOMAIN_SUBSTRING = "axestrack"

GOOGLE_SHEET_ID = os.environ["GOOGLE_SHEET_ID"]
GOOGLE_SHEET_TAB = os.environ.get("GOOGLE_SHEET_TAB", "Sheet2")
GOOGLE_SERVICE_ACCOUNT_JSON = json.loads(os.environ["GOOGLE_SERVICE_ACCOUNT_JSON"])

# FIREFLIES_ACCOUNTS: JSON array, one entry per HR's Fireflies account:
#   [{"label": "aryan", "webhook_secret": "...", "api_key": "..."}, ...]
# Each account MUST have a genuinely unique webhook_secret - it's the only
# signal that tells two accounts' webhooks apart (see module docstring).
try:
    FIREFLIES_ACCOUNTS = json.loads(os.environ["FIREFLIES_ACCOUNTS"])
except (KeyError, json.JSONDecodeError) as e:
    raise RuntimeError(
        "FIREFLIES_ACCOUNTS env var is missing or not valid JSON - expected "
        '\'[{"label": "...", "webhook_secret": "...", "api_key": "..."}, ...]\''
    ) from e

if not isinstance(FIREFLIES_ACCOUNTS, list) or not FIREFLIES_ACCOUNTS:
    raise RuntimeError("FIREFLIES_ACCOUNTS must be a non-empty JSON array")

for i, acct in enumerate(FIREFLIES_ACCOUNTS):
    for field in ("label", "webhook_secret", "api_key"):
        if not acct.get(field):
            raise RuntimeError(f"FIREFLIES_ACCOUNTS[{i}] is missing required field {field!r}")

_secrets_seen = {}
for acct in FIREFLIES_ACCOUNTS:
    prior = _secrets_seen.get(acct["webhook_secret"])
    if prior:
        raise RuntimeError(
            f"Duplicate webhook_secret in FIREFLIES_ACCOUNTS: accounts "
            f"{prior!r} and {acct['label']!r} share the same secret - each "
            f"account MUST have a genuinely unique secret, or their webhooks "
            f"can never be told apart (this refuses to start rather than "
            f"silently misattributing one account's data to the other)."
        )
    _secrets_seen[acct["webhook_secret"]] = acct["label"]

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


def identify_account(raw_body: bytes, signature_header: str):
    """
    Try the incoming signature against every configured account's secret.
    Returns the matching account dict ({label, webhook_secret, api_key}), or
    None if no account's secret produces a matching signature.
    """
    if not signature_header:
        return None

    # Fireflies sends the header as "sha256=<hex>" (v2 docs, confirmed) - strip the
    # prefix before comparing, or every real webhook would fail signature checks.
    received = signature_header
    if received.startswith("sha256="):
        received = received[len("sha256="):]

    for acct in FIREFLIES_ACCOUNTS:
        computed = hmac.new(
            acct["webhook_secret"].encode("utf-8"), raw_body, hashlib.sha256
        ).hexdigest()
        # constant-time compare - avoid leaking timing info about the correct signature
        if hmac.compare_digest(computed, received):
            return acct
    return None


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


def fetch_transcript(meeting_id: str, api_key: str) -> dict:
    resp = requests.post(
        FIREFLIES_GRAPHQL_URL,
        json={"query": TRANSCRIPT_QUERY, "variables": {"transcriptId": meeting_id}},
        headers={
            "Authorization": f"Bearer {api_key}",
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


def parse_online_start_datetime(date_string: str):
    """
    Full tz-aware IST datetime from Fireflies' dateString, used as the
    online meeting start time for converting segment elapsed-seconds to
    wall-clock time. Returns None if dateString is missing/unparseable -
    no guessing (see module docstring caveat re: whether dateString is
    truly the meeting start vs. transcript-creation time).
    """
    if not date_string:
        return None
    try:
        utc_dt = datetime.fromisoformat(date_string.replace("Z", "+00:00"))
        return utc_dt.astimezone(IST)
    except ValueError:
        return None


def strip_media_extension(part: str) -> str:
    # Fireflies sometimes uses the raw uploaded filename as the title, so a
    # trailing "_"-part can arrive with a media extension attached (e.g.
    # "06-09-2021.mp3" or "14-32.mp3" for date/time parts respectively).
    # Strip it before attempting to parse - a code fix rather than relying on
    # HR to remember to omit the extension when naming the upload.
    return re.sub(
        r"\.(mp3|m4a|wav|wave|ogg|flac|aac|webm|mp4|mov|avi|mkv)$", "", part, flags=re.IGNORECASE
    )


def parse_offline_title(title: str):
    """
    Parse the "Interviewer_Candidate_Date[_Time]" naming convention HR uses
    when manually uploading an offline MP3 through Fireflies' dashboard,
    e.g. "Priya_RahulSharma_04-09-2026" or, with a start time,
    "Priya_RahulSharma_04-09-2026_14-32" (HH-MM, 24h, dash not colon - colons
    aren't valid in Windows filenames). Only called for offline uploads
    (source already determined by meeting_link being absent) - this no
    longer decides source itself, just extracts names/date/time from the title.

    Returns (interviewer_name, candidate_name, meeting_date, start_datetime, warnings).
    meeting_date is the actual INTERVIEW date (distinct from
    meeting_upload_date, which always comes from Fireflies' own dateString
    regardless of source). start_datetime is a tz-aware IST datetime built
    from date+time (for converting segment elapsed-seconds to wall-clock
    time), or None if the date and/or time couldn't be determined.

    Neither value is ever backfilled from dateString - dateString is
    upload/processing time, not necessarily when the interview actually
    happened; a wrong-but-plausible guess is worse than an honest NULL here.

    Never raises - a malformed/missing title just means less gets parsed,
    logged as a warning, not a crash.
    """
    warnings = []
    title = (title or "").strip()
    parts = title.split("_") if title else []

    if len(parts) < 2:
        warnings.append(f"title {title!r} has fewer than 2 '_'-separated parts - interviewer/candidate left NULL")
        return None, None, None, None, warnings

    interviewer_name = parts[0].strip() or None
    candidate_name = parts[1].strip() or None
    meeting_date = None
    parsed_date = None  # datetime.date, kept alongside the isoformat string for start_datetime construction
    parsed_time = None  # datetime.time

    if len(parts) >= 3:
        date_part = strip_media_extension(parts[2].strip())
        # Example format from the convention: "04-09-2026" = DD-MM-YYYY
        for fmt in ("%d-%m-%Y", "%d-%m-%y", "%d/%m/%Y", "%Y-%m-%d"):
            try:
                parsed_date = datetime.strptime(date_part, fmt).date()
                meeting_date = parsed_date.isoformat()
                break
            except ValueError:
                continue
        if meeting_date is None:
            warnings.append(
                f"title date part {parts[2]!r} (stripped: {date_part!r}) did not match "
                f"any known format - meeting_date left NULL (not guessed from dateString)"
            )
    else:
        warnings.append(f"title {title!r} has no third part for date - meeting_date left NULL")

    if len(parts) >= 4:
        time_part = strip_media_extension(parts[3].strip())
        try:
            parsed_time = datetime.strptime(time_part, "%H-%M").time()
        except ValueError:
            warnings.append(
                f"title time part {parts[3]!r} (stripped: {time_part!r}) did not match "
                f"HH-MM format - segment clock times left NULL"
            )
    elif len(parts) < 4:
        warnings.append(f"title {title!r} has no 4th part for start time - segment clock times left NULL")

    start_datetime = None
    if parsed_date is not None and parsed_time is not None:
        start_datetime = IST.localize(datetime.combine(parsed_date, parsed_time))

    return interviewer_name, candidate_name, meeting_date, start_datetime, warnings


def fetch_hr_exclusion_emails() -> set:
    """
    Fetch the live HR-exclusion list from Google Sheets: single column
    "Email IDs" (column A, header row 1, emails from row 2), tab
    GOOGLE_SHEET_TAB in spreadsheet GOOGLE_SHEET_ID. Fetched fresh on every
    call (not cached) so edits to the sheet take effect immediately with no
    redeploy - this is a small, infrequent lookup, not a hot path.

    Returns a set of lowercased emails. On any failure (sheet unreachable,
    renamed tab, etc) logs a warning and returns an empty set - HR exclusion
    is a refinement, not something that should take the whole webhook down
    if the sheet is temporarily unavailable.
    """
    try:
        gc = gspread.service_account_from_dict(GOOGLE_SERVICE_ACCOUNT_JSON)
        ws = gc.open_by_key(GOOGLE_SHEET_ID).worksheet(GOOGLE_SHEET_TAB)
        values = ws.col_values(1)[1:]  # skip header row
        return {v.strip().lower() for v in values if v.strip()}
    except Exception as e:
        logger.warning(f"Could not fetch HR exclusion list from Google Sheet: {e}")
        return set()


def classify_online_participants(meeting_attendees: list, hr_exclusion_emails: set):
    """
    For a live online meeting: classify attendees by email domain.
    Any email whose domain CONTAINS "axestrack" (substring, not exact match -
    covers @axestrack.com, @ct.axestrack.com, @it.axestrack.com, etc) is a
    candidate interviewer, UNLESS their email is in hr_exclusion_emails (HR
    often opens/closes the call but isn't "the interviewer" for this row).

    After HR exclusion: 0 remaining -> interviewer_name NULL; 1 -> that
    person's displayName; 2+ -> comma-separated displayNames - genuinely
    ambiguous which one is "the" interviewer when more than one remains, so
    all of them are kept rather than arbitrarily picking one.

    Anyone with a non-axestrack domain -> candidate_name (first match).
    Multiple such participants is a real ambiguity (could be two candidates,
    or an external observer) - we pick the first and log a warning rather
    than guessing which one is "the" candidate.

    Returns (interviewer_name, candidate_name, warnings).
    """
    warnings = []
    interviewer_name = None
    candidate_name = None
    internal_matches = []
    excluded_matches = []
    external_matches = []

    for attendee in meeting_attendees or []:
        email = (attendee.get("email") or "").strip()
        display_name = (attendee.get("displayName") or "").strip() or email or None
        if not email:
            continue
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if INTERVIEWER_EMAIL_DOMAIN_SUBSTRING in domain:
            if email.lower() in hr_exclusion_emails:
                excluded_matches.append(display_name)
            else:
                internal_matches.append(display_name)
        else:
            external_matches.append(display_name)

    if excluded_matches:
        warnings.append(f"excluded HR participant(s) from interviewer classification: {excluded_matches}")

    if internal_matches:
        interviewer_name = ", ".join(internal_matches)
        if len(internal_matches) > 1:
            warnings.append(
                f"multiple non-excluded internal (*{INTERVIEWER_EMAIL_DOMAIN_SUBSTRING}*) participants "
                f"remained after HR exclusion: {internal_matches} - stored comma-separated in "
                f"interviewer_name rather than arbitrarily picking one"
            )

    if external_matches:
        candidate_name = external_matches[0]
        if len(external_matches) > 1:
            warnings.append(
                f"multiple non-{INTERVIEWER_EMAIL_DOMAIN_SUBSTRING} participants found "
                f"({external_matches}) - picked the first as candidate_name, "
                f"needs manual confirmation"
            )

    if interviewer_name is None:
        warnings.append(
            f"no non-excluded *{INTERVIEWER_EMAIL_DOMAIN_SUBSTRING}* participant found - "
            f"interviewer_name left NULL"
        )
    if candidate_name is None:
        warnings.append("no non-interviewer-domain participant found - candidate_name left NULL")

    return interviewer_name, candidate_name, warnings


def compute_clock_time(elapsed_seconds, start_datetime):
    """
    Convert an elapsed-seconds-into-the-recording offset to a wall-clock
    "HH:MM:SS" string (Asia/Kolkata), given the meeting/recording's actual
    start_datetime (tz-aware). Returns None if either input is missing -
    no guessing when the start time (or the offset itself) isn't known.
    """
    if start_datetime is None or elapsed_seconds is None:
        return None
    clock_dt = start_datetime + timedelta(seconds=elapsed_seconds)
    return clock_dt.strftime("%H:%M:%S")


def write_transcript_row(transcript: dict, meeting_id: str) -> dict:
    import uuid

    transcript_id = str(uuid.uuid4())
    meeting_name = transcript.get("title")
    meeting_link = transcript.get("meeting_link")
    sentences = transcript.get("sentences") or []

    # meeting_upload_date always comes from Fireflies' own dateString, regardless
    # of source - this is upload/processing time, not necessarily the interview date.
    meeting_upload_date = parse_meeting_date(transcript.get("dateString"))

    # meeting_link is the ONLY signal for offline vs online now (see module
    # docstring) - a real live meeting always has it populated; an uploaded
    # audio file never does.
    if meeting_link:
        source = "online"
        hr_exclusion_emails = fetch_hr_exclusion_emails()
        interviewer_name, candidate_name, warnings = classify_online_participants(
            transcript.get("meeting_attendees") or [], hr_exclusion_emails
        )
        # Online: the live call's date IS the interview date - same value.
        meeting_date = meeting_upload_date
        start_datetime = parse_online_start_datetime(transcript.get("dateString"))
        if start_datetime is None:
            warnings.append("no usable dateString for start time - segment clock times left NULL")
    else:
        source = "offline"
        interviewer_name, candidate_name, meeting_date, start_datetime, warnings = parse_offline_title(meeting_name)
        # Offline: meeting_date comes ONLY from the title (interview date). If the
        # title's date part is missing/unparseable, meeting_date stays None here -
        # deliberately not backfilled from meeting_upload_date (see parse_offline_title).

    for w in warnings:
        logger.warning(f"meeting_id={meeting_id} source={source} title={meeting_name!r}: {w}")

    if not sentences:
        raise RuntimeError(f"Transcript for meeting_id={meeting_id} has no sentences")

    segments = [
        {
            "segment_start": compute_clock_time(s.get("start_time"), start_datetime),
            "segment_end": compute_clock_time(s.get("end_time"), start_datetime),
            "speaker": s.get("speaker_name") or s.get("speaker_id") or "UNKNOWN",
            "text": (s.get("text") or "").strip(),
        }
        for s in sentences
    ]

    insert_sql = """
        INSERT INTO drt.ta_interview_transcript (
            transcript_id, source, meeting_upload_date, meeting_date, meeting_link,
            meeting_name, interviewer_name, candidate_name, segments
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        );
    """

    conn = psycopg2.connect(**DB_CONFIG, connect_timeout=10)
    try:
        cur = conn.cursor()
        cur.execute(insert_sql, (
            transcript_id,
            source,
            meeting_upload_date,
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

    account = identify_account(raw_body, signature)
    if account is None:
        logger.warning("Rejected webhook: signature didn't match any configured account")
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    # Webhooks V2 payload shape (confirmed against Fireflies' docs):
    # {"event": "meeting.transcribed", "timestamp": ..., "meeting_id": "...", "client_reference_id": "..."}
    event_type = payload.get("event")
    meeting_id = payload.get("meeting_id")

    logger.info(
        f"Received webhook: account={account['label']!r} event={event_type!r} meeting_id={meeting_id!r}"
    )

    if event_type != "meeting.transcribed":
        logger.info(f"Ignoring event {event_type!r} - only handling 'meeting.transcribed'")
        return {"status": "ignored", "reason": f"unhandled event: {event_type}"}

    if not meeting_id:
        logger.error("Webhook missing meeting_id")
        raise HTTPException(status_code=400, detail="Missing meeting_id")

    try:
        transcript = fetch_transcript(meeting_id, account["api_key"])
        result = write_transcript_row(transcript, meeting_id)
        logger.info(
            f"Wrote transcript_id={result['transcript_id']} account={account['label']!r} "
            f"source={result['source']!r} interviewer={result['interviewer_name']!r} "
            f"candidate={result['candidate_name']!r} segments={result['segment_count']} "
            f"meeting={result['meeting_name']!r}"
        )
        return {"status": "ok", "account": account["label"], **result}
    except Exception as e:
        logger.exception(f"Failed to process meeting_id={meeting_id}")
        # Return 500 so Fireflies' webhook delivery sees a failure (may retry per their policy) -
        # swallowing this and returning 200 would silently drop a real transcript.
        raise HTTPException(status_code=500, detail=str(e))
