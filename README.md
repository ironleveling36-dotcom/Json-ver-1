# Swiggy Auth Telegram Bot

Telegram bot that handles Swiggy OTP-based OAuth (PKCE) and returns session cookies as JSON.

## Commands
- `/start`, `/help` – Help menu
- `/login` – Start OTP login (asks mobile → OTP)
- `/status` – Show current session info
- `/cookies` – Download session JSON
- `/logout` – Clear session
- `/cancel` – Cancel active login

## Environment variables
| Key | Required | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | ✅ | Token from [@BotFather](https://t.me/BotFather) |
| `ADMIN_IDS` | ⛔ | Comma-separated Telegram user IDs |
| `DB_PATH` | ⛔ | SQLite path (default `/tmp/sessions.db`) |

## Local run
```bash
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN=xxxxx
python bot.py
```

## Deploy to Railway from GitHub

1. Push this folder to a GitHub repo.
2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo** → select your repo.
3. Railway auto-detects the `Dockerfile`.
4. In **Variables**, add:
   - `TELEGRAM_BOT_TOKEN` = your BotFather token
   - (optional) `ADMIN_IDS`
5. Deploy. Logs should show `Bot started.`

> Note: Railway's filesystem is ephemeral. The default `DB_PATH=/tmp/sessions.db` will reset on redeploy. For persistence, add a Railway Volume mounted at `/data` and set `DB_PATH=/data/sessions.db`.
