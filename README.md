# NextBot Gmail Push Backend (Hostinger-ready)

Hosted backend so app users can connect Gmail with OAuth and receive push-based new-email events without local ngrok/gcloud setup.

## What this service does

- Handles Google OAuth for Gmail per user
- Stores refresh tokens encrypted at rest
- Starts Gmail watch (`users.watch`) to your Pub/Sub topic
- Receives Pub/Sub push notifications on webhook endpoint
- Resolves new messages from Gmail history API
- Exposes app endpoints for status + notifications polling
- Includes internal endpoint to renew expiring Gmail watches

## Endpoints

- `GET /health`
- `GET /oauth/google/start?userId=<id>`
- `GET /oauth/google/callback`
- `POST /gmail/push?secret=<webhook-secret>`
- `GET /users/:userId/status` (requires `x-nextbot-secret`)
- `GET /users/:userId/notifications?limit=25&since=ISO` (requires `x-nextbot-secret`)
- `POST /users/:userId/watch-start` (requires `x-nextbot-secret`)
- `POST /users/:userId/disconnect` (requires `x-nextbot-secret`)
- `POST /internal/renew-watches` (requires `x-nextbot-secret`)

## 1) Prepare Google Cloud (one-time)

Use your project:
- `focused-studio-410607`

Topic and subscription:
- Topic: `projects/focused-studio-410607/topics/NEXTBOT`
- Subscription: `NEXTBOT-sub`

Grant Gmail publish permission:

```bash
gcloud config set project focused-studio-410607
gcloud services enable gmail.googleapis.com pubsub.googleapis.com
gcloud pubsub topics add-iam-policy-binding NEXTBOT \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher"
```

## 2) Configure backend env

Copy `.env.example` to `.env` and fill values:

- `BASE_URL` = your public backend URL (Hostinger domain)
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
- `APP_SHARED_SECRET` = secret your app uses for authenticated backend API calls
- `GMAIL_PUSH_WEBHOOK_SECRET` = secret in webhook query for Pub/Sub push
- `ENCRYPTION_KEY_B64` = 32-byte base64 key:

```bash
openssl rand -base64 32
```

## 3) Run the backend

```bash
cd apps/gmail-push-backend
node server.mjs
```

or:

```bash
npm start
```

## 4) Create Pub/Sub push subscription to backend webhook

Set endpoint:
- `https://YOUR_BACKEND_DOMAIN/gmail/push?secret=YOUR_GMAIL_PUSH_WEBHOOK_SECRET`

Create/update subscription:

```bash
gcloud pubsub subscriptions create NEXTBOT-sub \
  --topic=NEXTBOT \
  --push-endpoint="https://YOUR_BACKEND_DOMAIN/gmail/push?secret=YOUR_GMAIL_PUSH_WEBHOOK_SECRET" \
  --ack-deadline=10
```

If already exists:

```bash
gcloud pubsub subscriptions update NEXTBOT-sub \
  --push-endpoint="https://YOUR_BACKEND_DOMAIN/gmail/push?secret=YOUR_GMAIL_PUSH_WEBHOOK_SECRET" \
  --ack-deadline=10
```

## 5) App flow for each user

1. App opens:
   - `GET https://YOUR_BACKEND_DOMAIN/oauth/google/start?userId=<appUserId>`
2. User completes Google consent
3. Backend stores encrypted refresh token and starts Gmail watch
4. App checks:
   - `GET /users/:userId/status`
5. App polls notifications:
   - `GET /users/:userId/notifications`

All app-authenticated calls must send:

```http
x-nextbot-secret: <APP_SHARED_SECRET>
```

## 6) Renew watches (daily)

Gmail watches expire (typically ~7 days). Run this daily from a cron/job:

```bash
curl -X POST \
  -H "x-nextbot-secret: YOUR_APP_SHARED_SECRET" \
  https://YOUR_BACKEND_DOMAIN/internal/renew-watches
```

## Security notes

- Store `.env` outside git
- Rotate `APP_SHARED_SECRET` and webhook secret periodically
- Rotate `ENCRYPTION_KEY_B64` carefully (requires re-encrypt migration)
- Serve only behind HTTPS
- Restrict backend network access where possible

