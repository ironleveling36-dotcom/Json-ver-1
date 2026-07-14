# bot.py - Telegram Swiggy Auth Bot
import os
import json
import sqlite3
import logging
from datetime import datetime

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

from swiggy_auth import SwiggyAuth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_IDS = [
    int(i) for i in os.getenv("ADMIN_IDS", "").split(",") if i.strip().isdigit()
]

# Use /tmp on Railway (writable). Override with DB_PATH env if needed.
DB_PATH = os.getenv("DB_PATH", "/tmp/sessions.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            user_id INTEGER PRIMARY KEY,
            mobile TEXT,
            auth_data TEXT,
            cookies_json TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS pending_auth (
            user_id INTEGER PRIMARY KEY,
            mobile TEXT,
            otp_session_id TEXT,
            csrf_token TEXT,
            pkce_verifier TEXT,
            pkce_challenge TEXT,
            created_at TIMESTAMP
        )"""
    )
    conn.commit()
    conn.close()


class SwiggyAuthBot:
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.auth = SwiggyAuth(state_dir=f"/tmp/swiggy_{user_id}")

    def request_otp(self, mobile: str):
        try:
            session = self.auth.init_session(mobile)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                """INSERT OR REPLACE INTO pending_auth
                   (user_id, mobile, csrf_token, pkce_verifier, pkce_challenge, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    self.user_id,
                    mobile,
                    session["csrf_token"],
                    session["pkce_verifier"],
                    session["pkce_challenge"],
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            conn.close()
            return True, "OTP sent successfully!"
        except Exception as e:
            logger.exception("request_otp failed")
            return False, f"Failed: {e}"

    def verify_otp(self, otp: str):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT mobile, csrf_token, pkce_verifier, pkce_challenge FROM pending_auth WHERE user_id=?",
            (self.user_id,),
        )
        row = c.fetchone()
        if not row:
            conn.close()
            return False, "No pending OTP request. Please start /login again."

        mobile, csrf_token, pkce_verifier, _pkce_challenge = row

        try:
            tokens = self.auth.verify_otp(mobile, otp, csrf_token, pkce_verifier)
            cookies_json = json.dumps(
                {
                    "access_token": tokens.get("access_token"),
                    "refresh_token": tokens.get("refresh_token"),
                    "csrf_token": csrf_token,
                    "expires_at": tokens.get("expires_at"),
                    "mobile": mobile,
                    "user_id": tokens.get("user_id"),
                    "session_id": tokens.get("session_id"),
                    "cookies": tokens.get("cookies", {}),
                }
            )
            now = datetime.now().isoformat()
            c.execute(
                """INSERT OR REPLACE INTO sessions
                   (user_id, mobile, auth_data, cookies_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (self.user_id, mobile, json.dumps(tokens), cookies_json, now, now),
            )
            c.execute("DELETE FROM pending_auth WHERE user_id=?", (self.user_id,))
            conn.commit()
            conn.close()
            return True, cookies_json
        except Exception as e:
            conn.close()
            logger.exception("verify_otp failed")
            return False, f"OTP verification failed: {e}"

    def get_cookies_json(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT cookies_json FROM sessions WHERE user_id=?", (self.user_id,)
        )
        row = c.fetchone()
        conn.close()
        return row[0] if row else None


# ---------- Handlers ----------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    await update.message.reply_text(
        f"🐱 *Swiggy Auth Bot*\n\n"
        f"Hi {user.first_name}! I'll handle Swiggy authentication for you.\n\n"
        f"Commands:\n"
        f"/login - Start OTP login\n"
        f"/status - Check your session\n"
        f"/cookies - Get JSON cookies\n"
        f"/logout - Clear session\n"
        f"/help - Show this message",
        parse_mode="Markdown",
    )


async def login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📱 *Login to Swiggy*\n\n"
        "Please enter your mobile number with country code.\n"
        "Example: `+919876543210`\n\n"
        "Type /cancel to abort.",
        parse_mode="Markdown",
    )
    context.user_data["login_state"] = "awaiting_mobile"


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()
    if text.startswith("/"):
        return

    state = context.user_data.get("login_state")

    if state == "awaiting_mobile":
        if not text.startswith("+"):
            await update.message.reply_text(
                "❌ Please enter mobile with country code. Example: `+919876543210`",
                parse_mode="Markdown",
            )
            return
        context.user_data["mobile"] = text
        context.user_data["login_state"] = "awaiting_otp"

        bot = SwiggyAuthBot(user_id)
        success, msg = bot.request_otp(text)
        if success:
            await update.message.reply_text(
                f"✅ OTP sent to {text}\n\nEnter the 6-digit OTP.\nType /cancel to abort."
            )
        else:
            await update.message.reply_text(f"❌ {msg}\nStart again with /login")
            context.user_data["login_state"] = None

    elif state == "awaiting_otp":
        if not text.isdigit() or len(text) != 6:
            await update.message.reply_text("❌ Please enter a valid 6-digit OTP.")
            return
        bot = SwiggyAuthBot(user_id)
        success, result = bot.verify_otp(text)
        if success:
            await update.message.reply_text(
                "✅ *Login successful!*\n\nUse /cookies to retrieve your session JSON.",
                parse_mode="Markdown",
            )
            context.user_data["login_state"] = None
        else:
            await update.message.reply_text(f"❌ {result}\nTry again or /login")


async def cookies_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    bot = SwiggyAuthBot(user_id)
    cookies_json = bot.get_cookies_json()
    if cookies_json:
        await update.message.reply_document(
            document=("swiggy_cookies.json", cookies_json.encode()),
            caption="📄 Your Swiggy session cookies (JSON). Keep this secure!",
        )
    else:
        await update.message.reply_text("❌ No active session. Use /login first.")


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT mobile, created_at, updated_at FROM sessions WHERE user_id=?",
        (user_id,),
    )
    row = c.fetchone()
    conn.close()
    if row:
        mobile, created, updated = row
        await update.message.reply_text(
            f"✅ *Session Active*\n\n"
            f"📱 Mobile: `{mobile}`\n"
            f"🕐 Created: `{created}`\n"
            f"🔄 Updated: `{updated}`",
            parse_mode="Markdown",
        )
    else:
        await update.message.reply_text("❌ No active session. Use /login to authenticate.")


async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM pending_auth WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    context.user_data.clear()
    await update.message.reply_text("✅ Logged out. All session data cleared.")


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("❌ Login cancelled. Use /login to start again.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)


def main():
    if not TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable not set")

    init_db()

    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("login", login))
    app.add_handler(CommandHandler("cookies", cookies_cmd))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("logout", logout))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot started.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
