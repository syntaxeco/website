import threading, logging
from datetime import datetime
import requests
from config import Config

config = Config()

def SendAdminLog(title: str, description: str, actor=None, fields=None,
                 color: int = 0x3498DB, footer: str = "Syntax Admin Log"):
    """
    Post an admin audit-log embed to the Discord admin-logs webhook in a
    background thread. Mirrors LogAssetModerationAction. Never raises into
    the caller; failures are only logged.
    """
    if fields is None:
        fields = []
    author = None
    avatar_url = None
    if actor is not None:
        avatar_url = f"https://www.syntax.eco/Thumbs/Head.ashx?x=48&y=48&userId={str(actor.id)}"
        author = {"name": actor.username, "icon_url": avatar_url}
    EmbedObj = {
        "type": "rich",
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": footer},
        "timestamp": datetime.utcnow().isoformat(),
    }
    if author:
        EmbedObj["author"] = author
    payload = {"username": footer, "embeds": [EmbedObj]}
    if avatar_url:
        payload["avatar_url"] = avatar_url
    def thread_func():
        try:
            requests.post(url=config.DISCORD_ADMIN_LOGS_WEBHOOK, json=payload, timeout=10)
        except Exception as e:
            logging.warning(f"SendAdminLog: failed to send webhook - {str(e)}")
    threading.Thread(target=thread_func).start()
