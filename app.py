from flask import Flask, request, Response
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import os
import hmac
import hashlib
import asyncio
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
GITHUB_SECRET = os.getenv("GITHUB_SECRET")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET")

if not all([TELEGRAM_TOKEN, GITHUB_SECRET, TELEGRAM_CHAT_ID]):
    logger.error("Missing required environment variables: TELEGRAM_TOKEN, GITHUB_SECRET, or TELEGRAM_CHAT_ID")
    raise EnvironmentError("Environment variables not set")

if not GITHUB_SECRET:
    logger.error("GITHUB_SECRET must be a non-empty string")
    raise ValueError("Invalid GITHUB_SECRET")

GITHUB_SECRET = GITHUB_SECRET.encode()

async def init_bot():
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("GitHub notifications bot is active.")

    application.add_handler(CommandHandler("start", start))
    await application.initialize()
    return application

loop = asyncio.get_event_loop()
application = loop.run_until_complete(init_bot())

def run_async(coro):
    """
    Run an async coroutine in a thread-safe way using the existing event loop.
    """
    return loop.run_until_complete(coro)

@app.route("/telegram-webhook", methods=["POST"])
def telegram_webhook():
    try:

        if TELEGRAM_WEBHOOK_SECRET:
            auth_header = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
            if auth_header != TELEGRAM_WEBHOOK_SECRET:
                logger.warning("Invalid Telegram webhook secret token")
                return Response("Invalid secret token", status=403)

        update = request.get_json(force=True)
        if not update:
            logger.warning("Empty or invalid Telegram webhook payload")
            return Response("Invalid payload", status=400)


        run_async(application.process_update(Update.de_json(update, application.bot)))
        return Response("OK", status=200)

    except Exception as e:
        logger.error(f"Error processing Telegram webhook: {e}")
        return Response(f"Error: {e}", status=500)

@app.route("/github-webhook", methods=["POST"])
def github_webhook():
    try:

        signature = request.headers.get("X-Hub-Signature-256")
        if not signature:
            logger.warning("Missing GitHub signature header")
            return Response("Missing signature", status=403)

        payload = request.get_data()
        sha_name, signature_value = signature.split("=")
        if sha_name != "sha256":
            logger.warning("Unsupported signature algorithm")
            return Response("Invalid signature algorithm", status=403)

        mac = hmac.new(GITHUB_SECRET, msg=payload, digestmod=hashlib.sha256)
        if not hmac.compare_digest(mac.hexdigest(), signature_value):
            logger.warning("Invalid GitHub signature")
            return Response("Invalid signature", status=403)

        data = request.get_json()
        if not data:
            logger.warning("Empty or invalid GitHub webhook payload")
            return Response("Invalid payload", status=400)

        if request.headers.get("X-GitHub-Event") == "push":
            repo = data["repository"]["full_name"]
            pusher = data["pusher"]["name"]
            commit_msg = data.get("head_commit", {}).get("message", "No commit message")
            branch = data["ref"].split("/")[-1]  # Extract branch name (e.g., "main" from "refs/heads/main")
            commit_sha = data.get("head_commit", {}).get("id", "Unknown")
            timestamp = data.get("head_commit", {}).get("timestamp", "Unknown")
            repo_url = data["repository"]["html_url"]
            committer = data.get("head_commit", {}).get("committer", {}).get("name", "Unknown")
            changed_files = (
                len(data.get("head_commit", {}).get("added", [])) +
                len(data.get("head_commit", {}).get("modified", [])) +
                len(data.get("head_commit", {}).get("removed", []))
            )
            message = (
                f"📦 *Repo*: {repo} ({repo_url})\n"
                f"🌳 *Branch*: {branch}\n"
                f"👤 *Pusher*: {pusher}\n"
                f"✍️ *Committer*: {committer}\n"
                f"📝 *Commit*: {commit_msg}\n"
                f"🔗 *SHA*: {commit_sha[:7]}\n"
                f"📅 *Time*: {timestamp}\n"
                f"📂 *Changed Files*: {changed_files}"
            )

            run_async(application.bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode="Markdown"))
            logger.info(f"Sent Telegram message for push to {repo}")

        return Response("OK", status=200)

    except Exception as e:
        logger.error(f"Error processing GitHub webhook: {e}")
        return Response(f"Error: {e}", status=500)

if __name__ == "__main__":
    try:
        logger.info("Starting Flask server on port 5000")
        from waitress import serve
        serve(app, host="0.0.0.0", port=5000)
    except KeyboardInterrupt:
        logger.info("Shutting down server")
    finally:
        loop.run_until_complete(application.shutdown())