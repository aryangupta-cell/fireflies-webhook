# Fireflies webhook receiver — Render deployment

Deploy target: Render free web service (not the office server — no sudo access there for the nginx/systemd route this originally needed).

## Files
- `main.py` — the FastAPI app (webhook receiver + Fireflies GraphQL pull + interview_transcripts writer)
- `requirements.txt` — pinned to the exact versions already tested end-to-end

## Deploy steps (dashboard method — no render.yaml needed)

1. Push this folder to a GitHub repo (see main conversation for exact git commands).
2. On [render.com](https://render.com), New → Web Service → connect the GitHub repo.
3. Runtime: Python 3. Build command: `pip install -r requirements.txt`. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
4. Plan: Free.
5. Environment variables (Settings → Environment), add these 7 (values from the local `.env` — never commit them to git):
   - `FIREFLIES_API_KEY`
   - `FIREFLIES_WEBHOOK_SECRET` (use a real rotated value here, not `"a"` — that was only for local connectivity testing)
   - `DB_HOST`
   - `DB_PORT`
   - `DB_NAME`
   - `DB_USER`
   - `DB_PASSWORD`
6. Deploy. Render assigns a URL like `https://fireflies-webhook-xxxx.onrender.com`.
7. Webhook endpoint to give Fireflies: `<that URL>/webhook`
8. Health check (also use this for the uptime-pinger, see below): `<that URL>/`

## Keeping it awake (important)

Render's free tier spins the service down after 15 minutes of no inbound traffic, and a cold start takes ~1 minute to respond. Fireflies requires a 2xx response within **10 seconds** or the delivery is marked failed — and their docs do not document any retry mechanism for failed deliveries. So an idle receiver **will** miss real webhooks.

Fix: an external uptime-ping service hitting `<url>/` (the health check) every 5-10 minutes keeps it warm, well under the 15-minute spin-down threshold. UptimeRobot's free tier supports this (5-minute interval on the free plan).
