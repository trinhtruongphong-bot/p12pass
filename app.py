import os
import tempfile
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse

from telegram import Update, Document
from telegram.ext import (
    Application, ApplicationBuilder, CommandHandler, MessageHandler,
    ConversationHandler, ContextTypes, filters
)

from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates, serialize_key_and_certificates
)

# -------------------- ENV --------------------
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Thiếu TELEGRAM_BOT_TOKEN")

EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")  # Render tự cấp
SECRET_TOKEN = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
WEBHOOK_PATH = f"/webhook/{BOT_TOKEN}"

# Giới hạn file (16MB mặc định)
try:
    MAX_FILE_SIZE_MB = int(os.environ.get("MAX_FILE_SIZE_MB", "16"))
except ValueError:
    MAX_FILE_SIZE_MB = 16
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# -------------------- FastAPI app --------------------
app = FastAPI()

# PTB states
ASK_OLD_PASS, ASK_NEW_PASS = range(2)

# -------------------- Helpers --------------------
async def cleanup(paths, dirs=None):
    dirs = dirs or []
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    for d in dirs:
        try:
            if d and os.path.isdir(d):
                os.rmdir(d)
        except Exception:
            pass

def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}TB"

# -------------------- Handlers --------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Chào bạn! Gửi cho mình file .p12 để đổi mật khẩu.\n"
        "Quy trình: gửi .p12 → nhập mật khẩu cũ → nhập mật khẩu mới.\n"
        f"Giới hạn kích thước: {MAX_FILE_SIZE_MB}MB."
    )

async def handle_p12(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc: Document = update.message.document
    if not doc or not doc.file_name.lower().endswith(".p12"):
        await update.message.reply_text("Vui lòng gửi đúng file .p12.")
        return ConversationHandler.END

    if doc.file_size and doc.file_size > MAX_FILE_SIZE_BYTES:
        await update.message.reply_text(
            f"File quá lớn: {human_bytes(doc.file_size)} (giới hạn {MAX_FILE_SIZE_MB}MB)."
        )
        return ConversationHandler.END

    file = await doc.get_file()

    tmp_dir = tempfile.mkdtemp(prefix="p12bot_")
    input_path = os.path.join(tmp_dir, doc.file_name)
    await file.download_to_drive(custom_path=input_path)

    context.user_data["input_path"] = input_path
    context.user_data["tmp_dir"] = tmp_dir
    context.user_data["orig_name"] = doc.file_name

    await update.message.reply_text("Nhập **mật khẩu cũ** (hoặc để trống nếu không có):")
    return ASK_OLD_PASS

async def ask_old_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["old_pass"] = (update.message.text or "").strip()
    await update.message.reply_text("OK. Giờ nhập **mật khẩu mới**:")
    return ASK_NEW_PASS

async def ask_new_pass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    new_pass = (update.message.text or "").strip()
    input_path = context.user_data.get("input_path")
    tmp_dir = context.user_data.get("tmp_dir")
    old_pass = context.user_data.get("old_pass")
    orig_name = context.user_data.get("orig_name")

    if not input_path or not os.path.exists(input_path):
        await update.message.reply_text("Không tìm thấy file tạm. Gửi lại .p12 nhé.")
        return ConversationHandler.END

    try:
        with open(input_path, "rb") as f:
            p12_data = f.read()
        key, cert, addl = load_key_and_certificates(
            p12_data,
            None if old_pass == "" else old_pass.encode("utf-8")
        )
        if cert is None and key is None:
            await update.message.reply_text("File .p12 không hợp lệ.")
            await cleanup([input_path], [tmp_dir])
            return ConversationHandler.END
    except Exception:
        await update.message.reply_text("Sai mật khẩu cũ hoặc file .p12 lỗi.")
        await cleanup([input_path], [tmp_dir])
        return ConversationHandler.END

    output_path = None
    try:
        name = cert.subject.rfc4514_string().encode("utf-8") if cert else b""
        friendly_name = name[:64] if name else None

        new_p12 = serialize_key_and_certificates(
            name=friendly_name,
            key=key,
            cert=cert,
            cas=addl,
            encryption_algorithm=BestAvailableEncryption(new_pass.encode("utf-8"))
        )

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.splitext(orig_name)[0]
        output_name = f"{base}_repass_{ts}.p12"
        output_path = os.path.join(tmp_dir, output_name)

        with open(output_path, "wb") as f:
            f.write(new_p12)

        await update.message.reply_document(
            document=open(output_path, "rb"),
            filename=output_name,
            caption="Đã đổi mật khẩu file .p12 thành công!"
        )

    except Exception:
        await update.message.reply_text("Lỗi khi tạo file .p12 mới.")
    finally:
        await cleanup([p for p in (input_path, output_path) if p], [tmp_dir])
        context.user_data.clear()

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Đã hủy.")
    tmp = context.user_data.get("input_path")
    tmp_dir = context.user_data.get("tmp_dir")
    await cleanup([tmp], [tmp_dir])
    context.user_data.clear()
    return ConversationHandler.END

# -------------------- Build Application --------------------
application: Optional[Application] = (
    ApplicationBuilder()
    .token(BOT_TOKEN)
    .build()
)

conv = ConversationHandler(
    entry_points=[MessageHandler(filters.Document.FILE_EXTENSION("p12"), handle_p12)],
    states={
        ASK_OLD_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, ask_old_pass)],
        ASK_NEW_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, ask_new_pass)],
    },
    fallbacks=[CommandHandler("cancel", cancel)],
    allow_reentry=True
)

application.add_handler(CommandHandler("start", start))
application.add_handler(conv)

# -------------------- FastAPI lifecycle --------------------
@app.on_event("startup")
async def on_startup():
    await application.initialize()
    await application.start()

    base = (EXTERNAL_URL.rstrip("/") if EXTERNAL_URL else "")
    webhook_url = base + WEBHOOK_PATH

    await application.bot.set_webhook(
        url=webhook_url,
        secret_token=SECRET_TOKEN if SECRET_TOKEN else None,
        drop_pending_updates=True,
    )

    print(f"Webhook set: {webhook_url}")

@app.on_event("shutdown")
async def on_shutdown():
    try:
        await application.bot.delete_webhook()
    except Exception:
        pass
    await application.stop()
    await application.shutdown()

# -------------------- Health check --------------------
@app.get("/", response_class=PlainTextResponse)
async def health():
    return "ok"

# -------------------- Telegram webhook endpoint --------------------
@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    if SECRET_TOKEN:
        received = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if received != SECRET_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid secret token")

    data = await request.json()
    update = Update.de_json(data, application.bot)
    await application.process_update(update)
    return {"ok": True}
