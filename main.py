"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         Advanced Telegram Channel Protection Bot — Single-File Edition      ║
║                                                                              ║
║  Sections (in order):                                                        ║
║    1.  Imports                                                               ║
║    2.  Constants                                                             ║
║    3.  Configuration                                                         ║
║    4.  Logger                                                                ║
║    5.  Database                                                              ║
║    6.  Spam / Detection Utilities                                            ║
║    7.  Permission Helpers                                                    ║
║    8.  Alert Utilities                                                       ║
║    9.  Moderation Utilities                                                  ║
║   10.  Inline Keyboards                                                      ║
║   11.  Handlers: start / help                                                ║
║   12.  Handlers: stats                                                       ║
║   13.  Handlers: admin management                                            ║
║   14.  Handlers: manual moderation commands                                  ║
║   15.  Handlers: emergency                                                   ║
║   16.  Handlers: protection engine                                           ║
║   17.  Handlers: control panel                                               ║
║   18.  Application bootstrap & entry-point                                   ║
║                                                                              ║
║  Required environment variables:                                             ║
║    TELEGRAM_BOT_TOKEN  — the bot token from @BotFather                      ║
║    OWNER_ID            — one or more owner numeric IDs, comma-separated     ║
║    ALLOWED_CHAT_ID     — numeric ID of the channel to protect                ║
║    DATABASE_URL        — (optional) Postgres URL; falls back to SQLite       ║
║    BOT_DATABASE_PATH   — (optional) SQLite path; default: data/bot.db       ║
║    LOG_LEVEL           — (optional) Python log level; default: INFO         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# =============================================================================
# 1. IMPORTS
# =============================================================================
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps

from telegram import Chat, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, Update, User
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    ApplicationHandlerStop,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


# =============================================================================
# 2. CONSTANTS
# =============================================================================

# ---------------------------------------------------------------------------
# Protection flags: key → human-readable label shown in the panel
# ---------------------------------------------------------------------------
PROTECTION_FLAGS: dict[str, str] = {
    "block_empty":        "Block empty messages",
    "block_gif":          "Block GIFs / animations",
    "block_stickers":     "Block stickers",
    "block_video_note":   "Block circular videos",
    "block_voice":        "Block voice messages",
    "block_video":        "Block video messages",
    "block_document":     "Block files / documents",
    "block_poll":         "Block polls",
    "block_game":         "Block games",
    "block_contact":      "Block contacts",
    "block_location":     "Block locations / venues",
    "block_links":        "Block links",
    "links_admins_only":  "Allow links from admins only",
    "block_phone_numbers":"Block phone / contact numbers",
    "anti_mass_mention":  "Anti mass-mention",
    "anti_spam_hashtags": "Anti spammy hashtags",
    "anti_duplicate":     "Block duplicate / repeated content",
    "anti_flood":         "Anti-flood / rate-limit",
    "block_edited_media": "Block edited / replaced media",
    "block_edited_text":  "Block edited text messages",
}

# All flags default to OFF at first setup
DEFAULT_FLAG_VALUES: dict[str, bool] = {k: False for k in PROTECTION_FLAGS}

# ---------------------------------------------------------------------------
# Punishment modes
# ---------------------------------------------------------------------------
PUNISHMENT_MODES: dict[str, str] = {
    "delete_only":     "Delete only",
    "delete_warn":     "Delete + warn (auto-ban on limit)",
    "delete_mute":     "Delete + mute",
    "delete_ban":      "Delete + ban",
    "delete_restrict": "Delete + restrict",
}
DEFAULT_PUNISHMENT_MODE = "delete_only"

# ---------------------------------------------------------------------------
# Image handling modes
# ---------------------------------------------------------------------------
IMAGE_MODES: dict[str, str] = {
    "allow":       "Allow all images",
    "block_all":   "Block all images",
    "admins_only": "Allow images from admins only",
}
DEFAULT_IMAGE_MODE = "allow"

# ---------------------------------------------------------------------------
# English-message protection modes
# ---------------------------------------------------------------------------
ENGLISH_MODES: dict[str, str] = {
    "disabled":       "Disabled (allow all)",
    "delete_all":     "Delete all English messages",
    "admins_only":    "Allow English from admins only",
    "selected_users": "Allow English from selected users only",
}
DEFAULT_ENGLISH_MODE = "disabled"

# ---------------------------------------------------------------------------
# Telegram admin rights exposed by the bot panel
# ---------------------------------------------------------------------------
TELEGRAM_RIGHTS: dict[str, str] = {
    "can_post_messages":    "Post messages",
    "can_edit_messages":    "Edit messages",
    "can_delete_messages":  "Delete messages",
    "can_manage_chat":      "Manage chat",
    "can_invite_users":     "Invite users",
    "can_restrict_members": "Restrict members",
    "can_pin_messages":     "Pin messages",
    "can_promote_members":  "Add new admins",
    "can_manage_video_chats": "Manage video chats",
}

# Default Telegram rights granted when /promote is used: posting only
DEFAULT_TELEGRAM_RIGHTS: dict[str, bool] = {
    "can_post_messages":    True,
    "can_edit_messages":    False,
    "can_delete_messages":  False,
    "can_manage_chat":      False,
    "can_invite_users":     False,
    "can_restrict_members": False,
    "can_pin_messages":     False,
    "can_promote_members":  False,
    "can_manage_video_chats": False,
}

# ---------------------------------------------------------------------------
# Bot-level admin permissions (used internally by the bot's permission system)
# ---------------------------------------------------------------------------
ADMIN_PERMISSIONS: dict[str, str] = {
    "ban_members":      "Ban members",
    "mute_members":     "Mute members",
    "unmute_members":   "Unmute members",
    "delete_messages":  "Delete messages / warn",
    "manage_panel":     "Access the control panel",
}

# ---------------------------------------------------------------------------
# Rights the bot itself MUST have in the channel for full enforcement
# ---------------------------------------------------------------------------
REQUIRED_BOT_RIGHTS: list[str] = [
    "can_promote_members",
    "can_restrict_members",
    "can_delete_messages",
]

# ---------------------------------------------------------------------------
# Other defaults
# ---------------------------------------------------------------------------
DEFAULT_ALERT_TEMPLATE = (
    "⚠️ Violation detected\n"
    "Type: {violation}\n"
    "User: {name} ({username}) — ID: {user_id}\n"
    "Link: {link}\n"
    "Time: {time}\n"
    "Punishment: {punishment}\n"
    "Original message: {original}"
)
DEFAULT_MUTE_MINUTES = 60
DEFAULT_SPAM_THRESHOLDS: list[list[int]] = [[5, 5], [8, 10], [12, 20]]
DEFAULT_DUPLICATE_WINDOW_SECONDS = 60
DEFAULT_DUPLICATE_REPEAT_THRESHOLD = 3
DEFAULT_EMERGENCY_TRIGGER_COUNT = 0      # 0 = manual only
DEFAULT_FORBIDDEN_WORDS_ENABLED = False
DEFAULT_PHONE_PROTECTION_ENABLED = False


# =============================================================================
# 3. CONFIGURATION
# =============================================================================

def _parse_owner_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for chunk in raw.replace(" ", "").split(","):
        if chunk.lstrip("-").isdigit():
            ids.add(int(chunk))
    return ids


@dataclass(frozen=True)
class Config:
    """All bot settings loaded from environment variables."""
    bot_token: str
    owner_ids: set[int]
    database_path: str
    database_url: str | None
    log_level: str
    allowed_chat_id: int | None

    @classmethod
    def load(cls) -> "Config":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError(
                "TELEGRAM_BOT_TOKEN is not set. Add it in the Secrets / environment variables."
            )

        owner_raw = os.environ.get("OWNER_ID", "").strip()
        owner_ids = _parse_owner_ids(owner_raw)
        if not owner_ids:
            raise RuntimeError(
                "OWNER_ID is not set. Add your numeric Telegram user ID as OWNER_ID."
            )

        allowed_raw = os.environ.get("ALLOWED_CHAT_ID", "").strip()
        allowed_chat_id = int(allowed_raw) if allowed_raw.lstrip("-").isdigit() else None

        return cls(
            bot_token=token,
            owner_ids=owner_ids,
            database_path=os.environ.get("BOT_DATABASE_PATH", "data/bot.db"),
            database_url=os.environ.get("DATABASE_URL"),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
            allowed_chat_id=allowed_chat_id,
        )


config = Config.load()


# =============================================================================
# 4. LOGGER
# =============================================================================

os.makedirs(os.path.dirname(config.database_path) or "data", exist_ok=True)

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

logging.basicConfig(
    level=getattr(logging, config.log_level.upper(), logging.INFO),
    format=_LOG_FORMAT,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(os.path.dirname(config.database_path) or "data", "bot.log"),
            encoding="utf-8",
        ),
    ],
)

# Silence noisy third-party loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


log = get_logger("main")


# =============================================================================
# 5. DATABASE
# =============================================================================

_db_log = get_logger("database")


class Database:
    """
    SQLite persistence layer.

    A single synchronous connection guarded by a re-entrant lock is used.
    SQLite calls are fast enough for a channel-protection bot, and this keeps
    the code simple and dependency-free.
    """

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    # ------------------------------------------------------------------
    @contextmanager
    def _cursor(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ------------------------------------------------------------------
    def _init_schema(self):
        with self._cursor() as cur:
            # groups
            cur.execute(
                """CREATE TABLE IF NOT EXISTS groups (
                    chat_id   INTEGER PRIMARY KEY,
                    title     TEXT,
                    owner_id  INTEGER,
                    created_at REAL
                )"""
            )

            # settings
            cur.execute(
                """CREATE TABLE IF NOT EXISTS settings (
                    chat_id              INTEGER PRIMARY KEY,
                    flags                TEXT    NOT NULL,
                    punishment_mode      TEXT    NOT NULL,
                    mute_minutes         INTEGER NOT NULL,
                    ban_after_warnings   INTEGER NOT NULL,
                    alert_chat_id        INTEGER,
                    alert_template       TEXT    NOT NULL,
                    emergency_mode       INTEGER NOT NULL DEFAULT 0
                )"""
            )

            # --- incremental column migrations for settings ---
            cur.execute("PRAGMA table_info(settings)")
            settings_cols = {row["name"] for row in cur.fetchall()}

            _add_col = lambda col, ddl: (
                cur.execute(f"ALTER TABLE settings ADD COLUMN {col} {ddl}")
                if col not in settings_cols else None
            )
            _add_col("image_mode",                   f"TEXT    NOT NULL DEFAULT 'allow'")
            _add_col("public_alerts_enabled",         "INTEGER NOT NULL DEFAULT 0")
            _add_col(
                "spam_thresholds",
                f"TEXT NOT NULL DEFAULT '{json.dumps(DEFAULT_SPAM_THRESHOLDS)}'",
            )
            _add_col("duplicate_window_seconds",
                     f"INTEGER NOT NULL DEFAULT {DEFAULT_DUPLICATE_WINDOW_SECONDS}")
            _add_col("duplicate_repeat_threshold",
                     f"INTEGER NOT NULL DEFAULT {DEFAULT_DUPLICATE_REPEAT_THRESHOLD}")
            _add_col("emergency_trigger_count",
                     f"INTEGER NOT NULL DEFAULT {DEFAULT_EMERGENCY_TRIGGER_COUNT}")
            _add_col("emergency_violation_counter", "INTEGER NOT NULL DEFAULT 0")
            _add_col(
                "english_mode",
                f"TEXT NOT NULL DEFAULT '{DEFAULT_ENGLISH_MODE}'",
            )
            _add_col("english_selected_users", "TEXT NOT NULL DEFAULT '[]'")
            _add_col(
                "forbidden_words_enabled",
                f"INTEGER NOT NULL DEFAULT {1 if DEFAULT_FORBIDDEN_WORDS_ENABLED else 0}",
            )
            _add_col(
                "phone_protection_enabled",
                f"INTEGER NOT NULL DEFAULT {1 if DEFAULT_PHONE_PROTECTION_ENABLED else 0}",
            )

            # admins
            cur.execute(
                """CREATE TABLE IF NOT EXISTS admins (
                    chat_id    INTEGER,
                    user_id    INTEGER,
                    permissions TEXT   NOT NULL,
                    added_by   INTEGER,
                    added_at   REAL,
                    signature  TEXT,
                    PRIMARY KEY (chat_id, user_id)
                )"""
            )
            cur.execute("PRAGMA table_info(admins)")
            admin_cols = {row["name"] for row in cur.fetchall()}
            if "signature" not in admin_cols:
                cur.execute("ALTER TABLE admins ADD COLUMN signature TEXT")
            if "restricted" not in admin_cols:
                cur.execute("ALTER TABLE admins ADD COLUMN restricted INTEGER NOT NULL DEFAULT 0")
            if "telegram_rights" not in admin_cols:
                cur.execute(
                    "ALTER TABLE admins ADD COLUMN telegram_rights TEXT NOT NULL DEFAULT '%s'"
                    % json.dumps(DEFAULT_TELEGRAM_RIGHTS)
                )

            # warnings
            cur.execute(
                """CREATE TABLE IF NOT EXISTS warnings (
                    chat_id INTEGER,
                    user_id INTEGER,
                    count   INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (chat_id, user_id)
                )"""
            )

            # violation log
            cur.execute(
                """CREATE TABLE IF NOT EXISTS violation_log (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id        INTEGER,
                    user_id        INTEGER,
                    username       TEXT,
                    full_name      TEXT,
                    violation_type TEXT,
                    original_text  TEXT,
                    punishment     TEXT,
                    created_at     REAL
                )"""
            )

            # admin action log
            cur.execute(
                """CREATE TABLE IF NOT EXISTS admin_action_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id     INTEGER,
                    actor_id    INTEGER,
                    action      TEXT,
                    target_id   INTEGER,
                    details     TEXT,
                    created_at  REAL
                )"""
            )
            cur.execute("PRAGMA table_info(admin_action_log)")
            action_cols = {row["name"] for row in cur.fetchall()}
            if "success" not in action_cols:
                cur.execute("ALTER TABLE admin_action_log ADD COLUMN success INTEGER")
            if "telegram_response" not in action_cols:
                cur.execute("ALTER TABLE admin_action_log ADD COLUMN telegram_response TEXT")
            if "reason" not in action_cols:
                cur.execute("ALTER TABLE admin_action_log ADD COLUMN reason TEXT")

            # forbidden words
            cur.execute(
                """CREATE TABLE IF NOT EXISTS forbidden_words (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id  INTEGER,
                    word     TEXT NOT NULL,
                    added_by INTEGER,
                    added_at REAL,
                    UNIQUE(chat_id, word)
                )"""
            )

            # stats
            cur.execute(
                """CREATE TABLE IF NOT EXISTS stats (
                    chat_id          INTEGER PRIMARY KEY,
                    deleted_messages INTEGER NOT NULL DEFAULT 0,
                    edit_attempts    INTEGER NOT NULL DEFAULT 0,
                    gifs_deleted     INTEGER NOT NULL DEFAULT 0,
                    banned_count     INTEGER NOT NULL DEFAULT 0,
                    muted_count      INTEGER NOT NULL DEFAULT 0,
                    warnings_count   INTEGER NOT NULL DEFAULT 0
                )"""
            )

            # message cache (for duplicate / edit detection)
            cur.execute(
                """CREATE TABLE IF NOT EXISTS message_cache (
                    chat_id        INTEGER,
                    message_id     INTEGER,
                    user_id        INTEGER,
                    media_signature TEXT,
                    text           TEXT,
                    created_at     REAL,
                    PRIMARY KEY (chat_id, message_id)
                )"""
            )

            # managed chats — channels and groups the bot actively protects
            cur.execute(
                """CREATE TABLE IF NOT EXISTS managed_chats (
                    chat_id   INTEGER PRIMARY KEY,
                    title     TEXT,
                    added_by  INTEGER,
                    added_at  REAL
                )"""
            )
            # Seed from ALLOWED_CHAT_ID if present and not already stored
            if config.allowed_chat_id is not None:
                cur.execute(
                    "SELECT chat_id FROM managed_chats WHERE chat_id=?",
                    (config.allowed_chat_id,),
                )
                if cur.fetchone() is None:
                    cur.execute(
                        "INSERT INTO managed_chats (chat_id, title, added_by, added_at) VALUES (?,?,?,?)",
                        (config.allowed_chat_id, "Default (from ALLOWED_CHAT_ID)", 0, time.time()),
                    )

    # ---------------------------------------------------------------- groups
    def ensure_group(self, chat_id: int, title: str, owner_id: int | None = None):
        with self._cursor() as cur:
            cur.execute("SELECT chat_id FROM groups WHERE chat_id=?", (chat_id,))
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO groups (chat_id, title, owner_id, created_at) VALUES (?,?,?,?)",
                    (chat_id, title, owner_id, time.time()),
                )
            else:
                cur.execute("UPDATE groups SET title=? WHERE chat_id=?", (title, chat_id))
        self.ensure_settings(chat_id)
        self.ensure_stats(chat_id)

    # ------------------------------------------------------------ settings
    def ensure_settings(self, chat_id: int):
        with self._cursor() as cur:
            cur.execute("SELECT chat_id FROM settings WHERE chat_id=?", (chat_id,))
            if cur.fetchone() is None:
                cur.execute(
                    """INSERT INTO settings
                    (chat_id, flags, punishment_mode, mute_minutes, ban_after_warnings,
                     alert_chat_id, alert_template, emergency_mode, image_mode,
                     public_alerts_enabled, spam_thresholds, duplicate_window_seconds,
                     duplicate_repeat_threshold, emergency_trigger_count,
                     emergency_violation_counter)
                    VALUES (?,?,?,?,?,?,?,0,?,0,?,?,?,?,0)""",
                    (
                        chat_id,
                        json.dumps(DEFAULT_FLAG_VALUES),
                        DEFAULT_PUNISHMENT_MODE,
                        DEFAULT_MUTE_MINUTES,
                        3,
                        None,
                        DEFAULT_ALERT_TEMPLATE,
                        DEFAULT_IMAGE_MODE,
                        json.dumps(DEFAULT_SPAM_THRESHOLDS),
                        DEFAULT_DUPLICATE_WINDOW_SECONDS,
                        DEFAULT_DUPLICATE_REPEAT_THRESHOLD,
                        DEFAULT_EMERGENCY_TRIGGER_COUNT,
                    ),
                )

    def get_settings(self, chat_id: int) -> dict:
        self.ensure_settings(chat_id)
        with self._cursor() as cur:
            cur.execute("SELECT * FROM settings WHERE chat_id=?", (chat_id,))
            data = dict(cur.fetchone())
            data["flags"] = json.loads(data["flags"])
            try:
                data["spam_thresholds"] = json.loads(data["spam_thresholds"])
            except (TypeError, ValueError):
                data["spam_thresholds"] = list(DEFAULT_SPAM_THRESHOLDS)
            return data

    def set_flag(self, chat_id: int, flag: str, value: bool):
        settings = self.get_settings(chat_id)
        settings["flags"][flag] = value
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET flags=? WHERE chat_id=?",
                (json.dumps(settings["flags"]), chat_id),
            )

    def set_punishment_mode(self, chat_id: int, mode: str):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET punishment_mode=? WHERE chat_id=?", (mode, chat_id)
            )

    def set_mute_minutes(self, chat_id: int, minutes: int):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET mute_minutes=? WHERE chat_id=?", (minutes, chat_id)
            )

    def set_ban_after_warnings(self, chat_id: int, count: int):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET ban_after_warnings=? WHERE chat_id=?", (count, chat_id)
            )

    def set_alert_chat(self, chat_id: int, alert_chat_id: int | None):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET alert_chat_id=? WHERE chat_id=?",
                (alert_chat_id, chat_id),
            )

    def set_alert_template(self, chat_id: int, template: str):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET alert_template=? WHERE chat_id=?",
                (template, chat_id),
            )

    def set_emergency_mode(self, chat_id: int, enabled: bool):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET emergency_mode=? WHERE chat_id=?",
                (1 if enabled else 0, chat_id),
            )

    def set_image_mode(self, chat_id: int, mode: str):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET image_mode=? WHERE chat_id=?", (mode, chat_id)
            )

    def set_public_alerts_enabled(self, chat_id: int, enabled: bool):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET public_alerts_enabled=? WHERE chat_id=?",
                (1 if enabled else 0, chat_id),
            )

    def set_spam_thresholds(self, chat_id: int, thresholds: list[list[int]]):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET spam_thresholds=? WHERE chat_id=?",
                (json.dumps(thresholds), chat_id),
            )

    def set_duplicate_settings(self, chat_id: int, window_seconds: int, repeat_threshold: int):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET duplicate_window_seconds=?, duplicate_repeat_threshold=? WHERE chat_id=?",
                (window_seconds, repeat_threshold, chat_id),
            )

    def set_emergency_trigger_count(self, chat_id: int, count: int):
        """0 disables auto-triggering entirely."""
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET emergency_trigger_count=? WHERE chat_id=?",
                (count, chat_id),
            )

    def increment_emergency_violation_counter(self, chat_id: int) -> int:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET emergency_violation_counter = emergency_violation_counter + 1 WHERE chat_id=?",
                (chat_id,),
            )
            cur.execute(
                "SELECT emergency_violation_counter FROM settings WHERE chat_id=?", (chat_id,)
            )
            return cur.fetchone()["emergency_violation_counter"]

    def reset_emergency_violation_counter(self, chat_id: int):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET emergency_violation_counter=0 WHERE chat_id=?", (chat_id,)
            )

    def set_english_mode(self, chat_id: int, mode: str):
        with self._cursor() as cur:
            cur.execute("UPDATE settings SET english_mode=? WHERE chat_id=?", (mode, chat_id))

    def get_english_selected_users(self, chat_id: int) -> list[int]:
        settings = self.get_settings(chat_id)
        try:
            return json.loads(settings.get("english_selected_users") or "[]")
        except (TypeError, ValueError):
            return []

    def set_english_selected_users(self, chat_id: int, user_ids: list[int]):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET english_selected_users=? WHERE chat_id=?",
                (json.dumps(user_ids), chat_id),
            )

    def add_english_selected_user(self, chat_id: int, user_id: int):
        users = set(self.get_english_selected_users(chat_id))
        users.add(user_id)
        self.set_english_selected_users(chat_id, sorted(users))

    def remove_english_selected_user(self, chat_id: int, user_id: int):
        users = set(self.get_english_selected_users(chat_id))
        users.discard(user_id)
        self.set_english_selected_users(chat_id, sorted(users))

    def set_forbidden_words_enabled(self, chat_id: int, enabled: bool):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET forbidden_words_enabled=? WHERE chat_id=?",
                (1 if enabled else 0, chat_id),
            )

    def set_phone_protection_enabled(self, chat_id: int, enabled: bool):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE settings SET phone_protection_enabled=? WHERE chat_id=?",
                (1 if enabled else 0, chat_id),
            )

    # ---------------------------------------------------- forbidden words
    def add_forbidden_word(self, chat_id: int, word: str, added_by: int) -> bool:
        word = word.strip()
        if not word:
            return False
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO forbidden_words (chat_id, word, added_by, added_at)
                VALUES (?,?,?,?) ON CONFLICT(chat_id, word) DO NOTHING""",
                (chat_id, word.lower(), added_by, time.time()),
            )
            return cur.rowcount > 0

    def add_forbidden_words_bulk(self, chat_id: int, words: list[str], added_by: int) -> int:
        return sum(1 for w in words if self.add_forbidden_word(chat_id, w, added_by))

    def remove_forbidden_word(self, chat_id: int, word: str) -> bool:
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM forbidden_words WHERE chat_id=? AND word=?",
                (chat_id, word.strip().lower()),
            )
            return cur.rowcount > 0

    def list_forbidden_words(self, chat_id: int) -> list[str]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT word FROM forbidden_words WHERE chat_id=? ORDER BY word", (chat_id,)
            )
            return [row["word"] for row in cur.fetchall()]

    def search_forbidden_words(self, chat_id: int, query: str) -> list[str]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT word FROM forbidden_words WHERE chat_id=? AND word LIKE ? ORDER BY word",
                (chat_id, f"%{query.strip().lower()}%"),
            )
            return [row["word"] for row in cur.fetchall()]

    # ---------------------------------------------------------------- admins
    def is_owner(self, user_id: int) -> bool:
        return user_id in config.owner_ids

    def add_admin(
        self,
        chat_id: int,
        user_id: int,
        permissions: list[str],
        added_by: int,
        telegram_rights: dict | None = None,
    ):
        rights = telegram_rights if telegram_rights is not None else dict(DEFAULT_TELEGRAM_RIGHTS)
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO admins (chat_id, user_id, permissions, added_by, added_at, telegram_rights)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(chat_id, user_id) DO UPDATE SET
                    permissions=excluded.permissions,
                    telegram_rights=excluded.telegram_rights""",
                (chat_id, user_id, json.dumps(permissions), added_by, time.time(), json.dumps(rights)),
            )

    def remove_admin(self, chat_id: int, user_id: int):
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM admins WHERE chat_id=? AND user_id=?", (chat_id, user_id)
            )

    @staticmethod
    def _decode_admin_row(data: dict) -> dict:
        data["permissions"] = json.loads(data["permissions"])
        try:
            data["telegram_rights"] = json.loads(data.get("telegram_rights") or "{}")
        except (TypeError, ValueError):
            data["telegram_rights"] = {}
        merged = dict(DEFAULT_TELEGRAM_RIGHTS)
        merged.update(data["telegram_rights"])
        data["telegram_rights"] = merged
        return data

    def get_admin(self, chat_id: int, user_id: int) -> dict | None:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM admins WHERE chat_id=? AND user_id=?", (chat_id, user_id)
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._decode_admin_row(dict(row))

    def list_admins(self, chat_id: int) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM admins WHERE chat_id=?", (chat_id,))
            return [self._decode_admin_row(dict(row)) for row in cur.fetchall()]

    def is_admin_or_owner(self, chat_id: int, user_id: int) -> bool:
        if self.is_owner(user_id):
            return True
        admin = self.get_admin(chat_id, user_id)
        return admin is not None and not admin.get("restricted")

    def set_admin_signature(self, chat_id: int, user_id: int, signature: str):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE admins SET signature=? WHERE chat_id=? AND user_id=?",
                (signature, chat_id, user_id),
            )

    def get_admin_by_signature(self, chat_id: int, signature: str) -> dict | None:
        if not signature:
            return None
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM admins WHERE chat_id=? AND signature=?",
                (chat_id, signature),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._decode_admin_row(dict(row))

    def set_admin_telegram_right(self, chat_id: int, user_id: int, right: str, value: bool) -> dict:
        """Updates one stored Telegram right and returns the full merged rights dict."""
        admin = self.get_admin(chat_id, user_id)
        rights = admin["telegram_rights"] if admin else dict(DEFAULT_TELEGRAM_RIGHTS)
        rights[right] = value
        with self._cursor() as cur:
            cur.execute(
                "UPDATE admins SET telegram_rights=? WHERE chat_id=? AND user_id=?",
                (json.dumps(rights), chat_id, user_id),
            )
        return rights

    def set_admin_restricted(self, chat_id: int, user_id: int, restricted: bool):
        """Flags an admin as restricted without removing their record."""
        with self._cursor() as cur:
            cur.execute(
                "UPDATE admins SET restricted=? WHERE chat_id=? AND user_id=?",
                (1 if restricted else 0, chat_id, user_id),
            )

    def restrict_all_admins(self, chat_id: int) -> list[dict]:
        """Marks every currently-unrestricted admin as restricted. Returns newly restricted ones."""
        admins = [a for a in self.list_admins(chat_id) if not a.get("restricted")]
        if not admins:
            return []
        with self._cursor() as cur:
            cur.execute("UPDATE admins SET restricted=1 WHERE chat_id=?", (chat_id,))
        for admin in admins:
            admin["restricted"] = 1
        return admins

    def unrestrict_all_admins(self, chat_id: int) -> list[dict]:
        """Clears the restricted flag for every admin. Returns the ones that were restricted before."""
        admins = [a for a in self.list_admins(chat_id) if a.get("restricted")]
        if not admins:
            return []
        with self._cursor() as cur:
            cur.execute("UPDATE admins SET restricted=0 WHERE chat_id=?", (chat_id,))
        for admin in admins:
            admin["restricted"] = 0
        return admins

    def has_permission(self, chat_id: int, user_id: int, permission: str) -> bool:
        if self.is_owner(user_id):
            return True
        admin = self.get_admin(chat_id, user_id)
        if admin is None or admin.get("restricted"):
            return False
        return permission in admin["permissions"]

    # ---------------------------------------------------------- warnings
    def add_warning(self, chat_id: int, user_id: int) -> int:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO warnings (chat_id, user_id, count) VALUES (?,?,1)
                ON CONFLICT(chat_id, user_id) DO UPDATE SET count = count + 1""",
                (chat_id, user_id),
            )
            cur.execute(
                "SELECT count FROM warnings WHERE chat_id=? AND user_id=?",
                (chat_id, user_id),
            )
            count = cur.fetchone()["count"]
        self.increment_stat(chat_id, "warnings_count")
        return count

    def reset_warnings(self, chat_id: int, user_id: int):
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)
            )

    def get_warnings(self, chat_id: int, user_id: int) -> int:
        with self._cursor() as cur:
            cur.execute(
                "SELECT count FROM warnings WHERE chat_id=? AND user_id=?",
                (chat_id, user_id),
            )
            row = cur.fetchone()
            return row["count"] if row else 0

    # ---------------------------------------------------------------- logs
    def log_violation(
        self,
        chat_id: int,
        user_id: int,
        username: str,
        full_name: str,
        violation_type: str,
        original_text: str,
        punishment: str,
    ):
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO violation_log
                (chat_id, user_id, username, full_name, violation_type,
                 original_text, punishment, created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (chat_id, user_id, username, full_name, violation_type,
                 original_text, punishment, time.time()),
            )

    def get_recent_violations(self, chat_id: int, limit: int = 15) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM violation_log WHERE chat_id=? ORDER BY id DESC LIMIT ?",
                (chat_id, limit),
            )
            return [dict(row) for row in cur.fetchall()]

    def log_admin_action(
        self,
        chat_id: int,
        actor_id: int,
        action: str,
        target_id: int | None,
        details: str = "",
        success: bool | None = None,
        telegram_response: str = "",
        reason: str = "",
    ):
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO admin_action_log
                (chat_id, actor_id, action, target_id, details, created_at,
                 success, telegram_response, reason)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    chat_id, actor_id, action, target_id, details, time.time(),
                    None if success is None else (1 if success else 0),
                    telegram_response, reason,
                ),
            )

    def get_recent_admin_actions(self, chat_id: int, limit: int = 15) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM admin_action_log WHERE chat_id=? ORDER BY id DESC LIMIT ?",
                (chat_id, limit),
            )
            return [dict(row) for row in cur.fetchall()]

    # ----------------------------------------------------------------- stats
    def ensure_stats(self, chat_id: int):
        with self._cursor() as cur:
            cur.execute("SELECT chat_id FROM stats WHERE chat_id=?", (chat_id,))
            if cur.fetchone() is None:
                cur.execute("INSERT INTO stats (chat_id) VALUES (?)", (chat_id,))

    def increment_stat(self, chat_id: int, field: str, amount: int = 1):
        self.ensure_stats(chat_id)
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE stats SET {field} = {field} + ? WHERE chat_id=?",
                (amount, chat_id),
            )

    def get_stats(self, chat_id: int) -> dict:
        self.ensure_stats(chat_id)
        with self._cursor() as cur:
            cur.execute("SELECT * FROM stats WHERE chat_id=?", (chat_id,))
            return dict(cur.fetchone())

    def get_most_violating_user(self, chat_id: int) -> tuple[int, int] | None:
        with self._cursor() as cur:
            cur.execute(
                """SELECT user_id, COUNT(*) as cnt FROM violation_log
                WHERE chat_id=? GROUP BY user_id ORDER BY cnt DESC LIMIT 1""",
                (chat_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return row["user_id"], row["cnt"]

    # --------------------------------------------------------------- caching
    def cache_message(
        self,
        chat_id: int,
        message_id: int,
        user_id: int,
        media_signature: str | None,
        text: str | None,
    ):
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO message_cache
                (chat_id, message_id, user_id, media_signature, text, created_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(chat_id, message_id) DO UPDATE SET
                    media_signature=excluded.media_signature,
                    text=excluded.text""",
                (chat_id, message_id, user_id, media_signature, text, time.time()),
            )

    def get_cached_message(self, chat_id: int, message_id: int) -> dict | None:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM message_cache WHERE chat_id=? AND message_id=?",
                (chat_id, message_id),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def prune_message_cache(self, max_age_seconds: int = 3600):
        cutoff = time.time() - max_age_seconds
        with self._cursor() as cur:
            cur.execute("DELETE FROM message_cache WHERE created_at < ?", (cutoff,))

    # -------------------------------------------------------- managed chats
    def add_managed_chat(self, chat_id: int, title: str, added_by: int) -> bool:
        """Adds a chat to the managed list. Returns True if newly added."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO managed_chats (chat_id, title, added_by, added_at)
                VALUES (?,?,?,?)
                ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title""",
                (chat_id, title, added_by, time.time()),
            )
            newly_added = cur.rowcount > 0
        # Ensure settings and stats rows exist for this chat
        self.ensure_settings(chat_id)
        self.ensure_stats(chat_id)
        return newly_added

    def remove_managed_chat(self, chat_id: int) -> bool:
        """Removes a chat from the managed list. Returns True if it existed."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM managed_chats WHERE chat_id=?", (chat_id,))
            return cur.rowcount > 0

    def list_managed_chats(self) -> list[dict]:
        """Returns all currently managed chats."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM managed_chats ORDER BY added_at")
            return [dict(row) for row in cur.fetchall()]

    def is_managed_chat(self, chat_id: int) -> bool:
        """True if this chat_id is in the managed list."""
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM managed_chats WHERE chat_id=?", (chat_id,))
            return cur.fetchone() is not None

    def get_managed_chat(self, chat_id: int) -> dict | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM managed_chats WHERE chat_id=?", (chat_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_managed_chat_title(self, chat_id: int, title: str):
        with self._cursor() as cur:
            cur.execute(
                "UPDATE managed_chats SET title=? WHERE chat_id=?", (title, chat_id)
            )


# Singleton database instance
db = Database(config.database_path)


# =============================================================================
# 6. SPAM / DETECTION UTILITIES
# =============================================================================

_message_times: dict[tuple[int, int], deque] = defaultdict(deque)
_recent_message_ids: dict[tuple[int, int], deque] = defaultdict(deque)
_recent_content: dict[tuple[int, int], deque] = defaultdict(deque)

# ---------------------------------------------------------------------------
# Compiled patterns — built once at import time
# ---------------------------------------------------------------------------

SIMPLE_URL_PATTERN = re.compile(r"(https?://|www\.|t\.me/)", re.IGNORECASE)
HASHTAG_PATTERN = re.compile(r"#\w+")
MENTION_PATTERN = re.compile(r"@\w{4,32}")
LATIN_LETTER_PATTERN = re.compile(r"[A-Za-z]")

# Curated list of common / abused TLDs for the generic domain detector
_TLDS = [
    "co.uk", "co.in", "com.au", "com.br", "co.jp", "com.tr",
    "com", "net", "org", "io", "ai", "dev", "app", "gg", "co", "live", "site",
    "shop", "store", "cloud", "online", "tech", "xyz", "me", "info", "biz",
    "click", "top", "pro", "name", "tv", "cc", "ws", "mobi", "link", "icu",
    "bet", "casino", "win", "bid", "loan", "download", "stream", "fun",
    "buzz", "monster", "rest", "today", "world", "life", "news", "media",
    "agency", "company", "group", "team", "zone", "space", "website",
    "email", "chat", "social", "network", "digital", "systems", "solutions",
    "services", "studio", "design",
    "us", "uk", "ca", "de", "fr", "ru", "cn", "jp", "kr", "in", "au",
    "nl", "es", "it", "se", "no", "dk", "fi", "pl", "tr", "sa", "ae",
    "eg", "iq", "jo", "kw", "qa", "bh", "om", "ye", "ly", "ma", "dz",
    "tn", "sy", "lb", "ps", "ir", "pk", "id", "my", "sg", "vn", "th",
    "hk", "nz", "za", "ng", "ke", "mx",
]
_TLD_ALTERNATION = "|".join(sorted(set(_TLDS), key=len, reverse=True))

GENERIC_DOMAIN_PATTERN = re.compile(
    r"(?<![\w@])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}"
    r"(?:" + _TLD_ALTERNATION + r")"
    r"(?![a-z0-9-])",
    re.IGNORECASE,
)

TELEGRAM_LINK_PATTERN = re.compile(
    r"(t\.me/|telegram\.me/|telegram\.dog/|tg://)", re.IGNORECASE
)
DISCORD_INVITE_PATTERN = re.compile(
    r"(discord\.gg/|discord(?:app)?\.com/invite/)", re.IGNORECASE
)
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(\s*\S+?\s*\)")
HTML_LINK_PATTERN = re.compile(r"<a\s+[^>]*href\s*=", re.IGNORECASE)

# Obfuscated dots: "example dot com", "example[.]com", "نقطة", etc.
_OBFUSCATED_DOT_PATTERN = re.compile(
    r"\s*[\[\(]?\s*(?:dot|dawt|نقطة)\s*[\]\)]?\s*", re.IGNORECASE
)

# Phone number candidates
PHONE_CANDIDATE_PATTERN = re.compile(
    r"(?<!\w)(\+|00)?\(?\d[\d\s\-()]{5,}\d(?!\w)"
)


def _normalize_for_link_scan(text: str) -> str:
    """Replace obfuscated dots so the link patterns can match them."""
    normalized = _OBFUSCATED_DOT_PATTERN.sub(".", text)
    normalized = re.sub(r"(?<=[a-zA-Z0-9])\s*,\s*(?=[a-zA-Z]{2,24}\b)", ".", normalized)
    return normalized


def contains_link(text: str) -> bool:
    """Robust link / invite detection: http(s), www, t.me, Discord invites,
    Markdown/HTML hyperlinks, obfuscated dots, and any generic <label>.<TLD>."""
    if not text:
        return False
    normalized = _normalize_for_link_scan(text)
    return (
        bool(SIMPLE_URL_PATTERN.search(normalized))
        or bool(TELEGRAM_LINK_PATTERN.search(normalized))
        or bool(DISCORD_INVITE_PATTERN.search(normalized))
        or bool(MARKDOWN_LINK_PATTERN.search(normalized))
        or bool(HTML_LINK_PATTERN.search(normalized))
        or bool(GENERIC_DOMAIN_PATTERN.search(normalized))
    )


def contains_phone_number(text: str) -> bool:
    """Detect local and international phone/contact numbers."""
    if not text:
        return False
    for match in PHONE_CANDIDATE_PATTERN.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 7 <= len(digits) <= 15:
            return True
    return False


def contains_english(text: str) -> bool:
    """True if the text contains at least one Latin letter."""
    return bool(text) and bool(LATIN_LETTER_PATTERN.search(text))


def find_forbidden_word(text: str, words: list[str]) -> str | None:
    """Case-insensitive, whole-word-first forbidden word lookup.
    Returns the matched word (as configured) or None."""
    if not text or not words:
        return None
    lowered = text.lower()
    for word in words:
        w = word.strip().lower()
        if not w:
            continue
        if any(not ch.isalnum() and not ch.isspace() for ch in w):
            if w in lowered:
                return word
            continue
        if re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", lowered, re.UNICODE):
            return word
    return None


def count_hashtags(text: str) -> int:
    return len(HASHTAG_PATTERN.findall(text)) if text else 0


def count_mentions(text: str) -> int:
    return len(MENTION_PATTERN.findall(text)) if text else 0


def is_mass_mention(text: str, threshold: int = 4) -> bool:
    return count_mentions(text) >= threshold


def is_spammy_hashtags(text: str, threshold: int = 5) -> bool:
    return count_hashtags(text) >= threshold


def is_empty_message(message) -> bool:
    """A message with no text and no meaningful media/caption is 'empty'."""
    if message.text and message.text.strip():
        return False
    if message.caption and message.caption.strip():
        return False
    media_fields = [
        message.photo, message.video, message.document, message.voice,
        message.video_note, message.sticker, message.animation, message.audio,
        message.poll, message.game, message.contact, message.location, message.venue,
    ]
    return not any(media_fields)


def media_signature(message) -> str | None:
    """Cheap fingerprint for detecting edit/replacement of media messages."""
    if message.photo:
        return f"photo:{message.photo[-1].file_unique_id}"
    if message.video:
        return f"video:{message.video.file_unique_id}"
    if message.document:
        return f"document:{message.document.file_unique_id}"
    if message.audio:
        return f"audio:{message.audio.file_unique_id}"
    if message.voice:
        return f"voice:{message.voice.file_unique_id}"
    if message.video_note:
        return f"video_note:{message.video_note.file_unique_id}"
    if message.animation:
        return f"animation:{message.animation.file_unique_id}"
    if message.sticker:
        return f"sticker:{message.sticker.file_unique_id}"
    return None


def content_signature(message) -> str | None:
    """Fingerprint for duplicate-content detection (same text or same media)."""
    sig = media_signature(message)
    if sig:
        return sig
    text = (message.text or message.caption or "").strip().lower()
    if not text:
        return None
    return "text:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_flood(
    chat_id: int, user_id: int, message_id: int, thresholds: list
) -> list[int] | None:
    """Registers a message and checks it against [count, seconds] thresholds.

    Returns the list of recent message IDs to delete if any threshold fires,
    otherwise None. Thresholds are checked independently (OR semantics).
    """
    key = (chat_id, user_id)
    now = time.time()

    times = _message_times[key]
    times.append(now)
    ids = _recent_message_ids[key]
    ids.append((message_id, now))

    max_window = max((w for _, w in thresholds), default=0)
    while times and now - times[0] > max_window:
        times.popleft()
    while ids and now - ids[0][1] > max_window:
        ids.popleft()

    triggered = False
    trigger_window = 0
    for count, window in thresholds:
        recent = [t for t in times if now - t <= window]
        if len(recent) >= count:
            triggered = True
            trigger_window = max(trigger_window, window)

    if not triggered:
        return None

    to_delete = [mid for mid, ts in ids if now - ts <= trigger_window]
    times.clear()
    ids.clear()
    return to_delete


def is_duplicate_content(
    chat_id: int,
    user_id: int,
    signature: str,
    window_seconds: int,
    repeat_threshold: int,
) -> bool:
    """True once the same content signature has been seen `repeat_threshold`
    times within `window_seconds` from the same author."""
    if not signature:
        return False
    key = (chat_id, user_id)
    now = time.time()
    dq = _recent_content[key]
    dq.append((signature, now))
    while dq and now - dq[0][1] > window_seconds:
        dq.popleft()
    matches = sum(1 for sig, _ in dq if sig == signature)
    if matches >= repeat_threshold:
        _recent_content[key] = deque((s, t) for s, t in dq if s != signature)
        return True
    return False


# =============================================================================
# 7. PERMISSION HELPERS
# =============================================================================

def get_target_chat_id() -> int | None:
    return config.allowed_chat_id


def is_group_admin_or_owner(chat_id: int, user_id: int) -> bool:
    return db.is_admin_or_owner(chat_id, user_id)


async def _reject_if_no_channel(update: Update) -> bool:
    if config.allowed_chat_id is None:
        await update.effective_message.reply_text(
            "No protected channel is configured yet. Set the ALLOWED_CHAT_ID environment variable."
        )
        return True
    return False


def require_owner(func):
    """Decorator: only the configured owner(s) may call this handler."""
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if user is None or not db.is_owner(user.id):
            if update.effective_message:
                await update.effective_message.reply_text(
                    "This command is restricted to the primary owner."
                )
            return
        return await func(update, context, *args, **kwargs)
    return wrapper


def require_permission(permission: str):
    """Decorator: user must have a specific internal bot permission."""
    def decorator(func):
        @wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user = update.effective_user
            if user is None:
                return
            if await _reject_if_no_channel(update):
                return
            chat_id = config.allowed_chat_id
            if not db.has_permission(chat_id, user.id, permission):
                if update.effective_message:
                    await update.effective_message.reply_text(
                        "You do not have permission to use this command."
                    )
                return
            return await func(update, context, *args, **kwargs)
        return wrapper
    return decorator


def require_admin_or_owner(func):
    """Decorator: user must be an admin or owner."""
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if user is None:
            return
        if await _reject_if_no_channel(update):
            return
        chat_id = config.allowed_chat_id
        if not db.is_admin_or_owner(chat_id, user.id):
            if update.effective_message:
                await update.effective_message.reply_text(
                    "This command is restricted to admins and the owner."
                )
            return
        return await func(update, context, *args, **kwargs)
    return wrapper


# =============================================================================
# 8. ALERT UTILITIES
# =============================================================================

_alert_log = get_logger("alerts")


def format_alert(
    chat_id: int,
    name: str,
    username: str,
    user_id: str,
    link: str,
    violation: str,
    punishment: str,
    original_message: str = "(not available)",
) -> str:
    settings = db.get_settings(chat_id)
    template = settings["alert_template"]
    return template.format(
        violation=violation,
        name=name,
        username=username,
        user_id=user_id,
        link=link,
        time=time.strftime("%Y-%m-%d %H:%M:%S"),
        punishment=punishment,
        original=original_message or "(not available)",
    )


def _private_alert_recipients(chat_id: int) -> set[int]:
    """Owner(s) + every registered admin of the protected channel."""
    recipients = set(config.owner_ids)
    for admin in db.list_admins(chat_id):
        recipients.add(admin["user_id"])
    return recipients


async def send_alert(
    context: ContextTypes.DEFAULT_TYPE,
    chat: Chat,
    violation: str,
    punishment: str,
    name: str = "Unknown",
    username: str = "no username",
    user_id: str = "not available (channel post)",
    link: str = "-",
    original_message_id: int | None = None,
    original_message: str = "(not available)",
):
    """
    Sends a violation alert.

    Private DMs to the Owner(s) and all admins are always sent (Telegram
    requires the recipient to have started a DM with the bot at least once).
    Public posting into the channel or a separate alerts chat is opt-in only.
    These messages are treated as immutable audit records — they are never
    edited after sending.
    """
    settings = db.get_settings(chat.id)
    text = format_alert(
        chat.id, name, username, user_id, link, violation, punishment, original_message
    )

    # 1. Private DMs — always
    for recipient_id in _private_alert_recipients(chat.id):
        try:
            await context.bot.send_message(chat_id=recipient_id, text=text)
            if original_message_id and settings.get("emergency_mode"):
                try:
                    await context.bot.forward_message(
                        chat_id=recipient_id,
                        from_chat_id=chat.id,
                        message_id=original_message_id,
                    )
                except TelegramError:
                    pass
        except TelegramError as exc:
            _alert_log.debug(
                "Could not DM alert to %s (have they started the bot?): %s",
                recipient_id, exc,
            )

    # 2. Public alert — opt-in only
    public_target = settings.get("alert_chat_id")
    post_publicly = bool(settings.get("public_alerts_enabled")) or public_target is not None
    if post_publicly:
        target_chat_id = public_target or chat.id
        try:
            await context.bot.send_message(chat_id=target_chat_id, text=text)
            if original_message_id and settings.get("emergency_mode"):
                try:
                    await context.bot.forward_message(
                        chat_id=target_chat_id,
                        from_chat_id=chat.id,
                        message_id=original_message_id,
                    )
                except TelegramError:
                    pass
        except TelegramError as exc:
            _alert_log.warning("Failed to send public alert for chat %s: %s", chat.id, exc)


# =============================================================================
# 9. MODERATION UTILITIES
# =============================================================================

_mod_log = get_logger("moderation")

RESTRICTED_PERMISSIONS = ChatPermissions(
    can_send_messages=False,
    can_send_audios=False,
    can_send_documents=False,
    can_send_photos=False,
    can_send_videos=False,
    can_send_video_notes=False,
    can_send_voice_notes=False,
    can_send_polls=False,
    can_send_other_messages=False,
    can_add_web_page_previews=False,
)

LIMITED_PERMISSIONS = ChatPermissions(
    can_send_messages=True,
    can_send_audios=False,
    can_send_documents=False,
    can_send_photos=False,
    can_send_videos=False,
    can_send_video_notes=False,
    can_send_voice_notes=False,
    can_send_polls=False,
    can_send_other_messages=False,
    can_add_web_page_previews=False,
)

FULL_PERMISSIONS = ChatPermissions(
    can_send_messages=True,
    can_send_audios=True,
    can_send_documents=True,
    can_send_photos=True,
    can_send_videos=True,
    can_send_video_notes=True,
    can_send_voice_notes=True,
    can_send_polls=True,
    can_send_other_messages=True,
    can_add_web_page_previews=True,
)

NO_ADMIN_RIGHTS = dict(
    can_manage_chat=False,
    can_post_messages=False,
    can_edit_messages=False,
    can_delete_messages=False,
    can_invite_users=False,
    can_restrict_members=False,
    can_pin_messages=False,
    can_promote_members=False,
    can_manage_video_chats=False,
)


async def delete_message_safe(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, message_id: int
) -> bool:
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        return True
    except TelegramError as exc:
        _mod_log.debug("Could not delete message %s in %s: %s", message_id, chat_id, exc)
        return False


async def mute_user(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, minutes: int
):
    until = int(time.time() + minutes * 60) if minutes > 0 else None
    await context.bot.restrict_chat_member(
        chat_id=chat_id,
        user_id=user_id,
        permissions=RESTRICTED_PERMISSIONS,
        until_date=until,
    )


async def unmute_user(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int
):
    await context.bot.restrict_chat_member(
        chat_id=chat_id,
        user_id=user_id,
        permissions=FULL_PERMISSIONS,
    )


async def ban_user(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)


async def unban_user(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    await context.bot.unban_chat_member(chat_id=chat_id, user_id=user_id, only_if_banned=True)


async def restrict_user(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    await context.bot.restrict_chat_member(
        chat_id=chat_id, user_id=user_id, permissions=LIMITED_PERMISSIONS
    )


async def check_bot_admin_rights(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int
) -> dict:
    """Returns a dict of right_name -> bool for the bot's own rights in the channel.
    If any value is False, real promote/restrict/demote calls will silently fail."""
    try:
        me = await context.bot.get_me()
        member = await context.bot.get_chat_member(chat_id=chat_id, user_id=me.id)
    except TelegramError as exc:
        _mod_log.warning("Could not check bot's own admin rights in %s: %s", chat_id, exc)
        return {right: False for right in REQUIRED_BOT_RIGHTS}
    return {right: bool(getattr(member, right, False)) for right in REQUIRED_BOT_RIGHTS}


async def apply_admin_rights(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, rights: dict
) -> bool:
    """Applies an exact set of Telegram admin rights to a user via promote_chat_member."""
    full_rights = dict(NO_ADMIN_RIGHTS)
    full_rights.update(rights)
    try:
        await context.bot.promote_chat_member(
            chat_id=chat_id, user_id=user_id, is_anonymous=False, **full_rights
        )
        return True
    except TelegramError as exc:
        _mod_log.warning(
            "Could not apply Telegram admin rights for %s in %s (bot likely lacks "
            "'can_promote_members'): %s",
            user_id, chat_id, exc,
        )
        return False


async def revoke_admin_rights(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int
) -> bool:
    """Removes a user's real Telegram admin rights by re-promoting with all False."""
    return await apply_admin_rights(context, chat_id, user_id, NO_ADMIN_RIGHTS)


async def apply_emergency_mode(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, actor_id: int, enabled: bool
) -> list[dict]:
    """Single source of truth for turning emergency mode on/off.

    ON  — restricts every current admin's real Telegram rights to nothing.
    OFF — re-grants each admin's stored rights and clears the restriction flag.
    Returns the admins that were restricted or restored.
    """
    db.set_emergency_mode(chat_id, enabled)
    db.reset_emergency_violation_counter(chat_id)

    if enabled:
        affected = db.restrict_all_admins(chat_id)
        action = "emergency_restrict"
    else:
        affected = db.unrestrict_all_admins(chat_id)
        action = "emergency_unrestrict"

    for admin in affected:
        if enabled:
            applied = await revoke_admin_rights(context, chat_id, admin["user_id"])
            details = f"telegram rights edited to none: {applied}"
            reason = "Emergency mode enabled"
        else:
            applied = await apply_admin_rights(
                context, chat_id, admin["user_id"], admin.get("telegram_rights") or {}
            )
            details = f"stored telegram rights re-applied: {applied}"
            reason = "Emergency mode disabled"
        db.log_admin_action(
            chat_id, actor_id, action, admin["user_id"], details,
            success=applied,
            telegram_response="OK" if applied else "rejected - bot lacks can_promote_members",
            reason=reason,
        )

    return affected


async def maybe_auto_trigger_emergency(
    context: ContextTypes.DEFAULT_TYPE, chat: Chat, violation_type: str
) -> None:
    """Counts channel-wide violations and auto-activates emergency mode at threshold.
    A threshold of 0 disables this feature. No-ops if emergency mode is already on."""
    settings = db.get_settings(chat.id)
    if settings.get("emergency_mode"):
        return
    trigger_count = settings.get("emergency_trigger_count", 0)
    if not trigger_count or trigger_count <= 0:
        return

    count = db.increment_emergency_violation_counter(chat.id)
    if count < trigger_count:
        return

    restricted = await apply_emergency_mode(context, chat.id, actor_id=0, enabled=True)
    db.log_admin_action(
        chat.id,
        actor_id=0,
        action="auto_emergency_triggered",
        target_id=None,
        details=(
            f"{count} violations reached threshold {trigger_count} "
            f"(last: {violation_type})"
        ),
    )
    notice = (
        f"Emergency mode auto-enabled: {count} violations reached the configured threshold "
        f"({trigger_count}). All admins have been restricted (posting/editing/deleting/managing "
        "disabled) — only you (Owner) have full access now. Turn emergency mode off from the "
        "panel when the situation is resolved."
    )
    for owner_id in config.owner_ids:
        try:
            await context.bot.send_message(chat_id=owner_id, text=notice)
        except TelegramError as exc:
            _mod_log.debug(
                "Could not notify owner %s of auto-triggered emergency mode: %s", owner_id, exc
            )
    _mod_log.warning(
        "Auto-triggered emergency mode for chat %s after %s violations (threshold %s); "
        "restricted admins: %s",
        chat.id, count, trigger_count, [a["user_id"] for a in restricted],
    )


async def enforce_punishment(
    context: ContextTypes.DEFAULT_TYPE,
    chat: Chat,
    user: User | None,
    violation_type: str,
    original_text: str = "",
    message_id: int | None = None,
    force_mode: str | None = None,
    author_signature: str | None = None,
    resolved_user_id: int | None = None,
    resolved_name: str | None = None,
    is_admin_violation: bool = False,
) -> str:
    """
    Deletes the offending message and applies the configured punishment.
    Returns a human-readable description of the action taken.

    `user` is None for anonymous channel posts (Bot API limitation: the
    identity of the channel post author is not exposed). If `resolved_user_id`
    is provided (resolved from the post's author signature), the punishment is
    applied to that user. Otherwise only deletion + logging + alerting happen.

    Administrators are NOT exempt. The Owner is always exempt — this function
    refuses to punish an owner ID even when explicitly asked.
    """
    target_id_preview = user.id if user is not None else resolved_user_id
    if target_id_preview is not None and db.is_owner(target_id_preview):
        _mod_log.info(
            "Ignoring punishment request against owner %s (owners are never punished).",
            target_id_preview,
        )
        return "No action (owner is exempt from automatic enforcement)"

    settings = db.get_settings(chat.id)
    mode = force_mode or settings["punishment_mode"]
    punishment_label = PUNISHMENT_MODES.get(mode, mode)

    # Zero-tolerance lockdown: while emergency mode is active, ANY violation
    # re-sweeps every registered admin and restricts them.
    if settings.get("emergency_mode"):
        swept = db.restrict_all_admins(chat.id)
        for admin in swept:
            revoked = await revoke_admin_rights(context, chat.id, admin["user_id"])
            db.log_admin_action(
                chat.id,
                actor_id=0,
                action="emergency_lockdown_restrict",
                target_id=admin["user_id"],
                details=(
                    f"triggered by violation: {violation_type} "
                    f"(telegram rights edited to none: {revoked})"
                ),
                success=revoked,
                telegram_response="OK" if revoked else "rejected - bot lacks can_promote_members",
                reason=f"Zero-tolerance lockdown sweep triggered by: {violation_type}",
            )

    if message_id:
        await delete_message_safe(context, chat.id, message_id)

    target_id = user.id if user is not None else resolved_user_id
    target_name = (
        user.full_name if user is not None else (resolved_name or "Unknown channel author")
    )
    target_username = (
        f"@{user.username}" if (user is not None and user.username) else "no username"
    )

    if target_id is None:
        # Anonymous channel post: deletion is the only possible action.
        punishment_label = "Deleted only (channel post — author could not be identified)"
        db.increment_stat(chat.id, "deleted_messages")
        db.log_violation(
            chat_id=chat.id,
            user_id=0,
            username="",
            full_name=author_signature or "Channel post",
            violation_type=violation_type,
            original_text=(original_text or "")[:500],
            punishment=punishment_label,
        )

        # If the post was signed but identity could not be resolved, trigger
        # emergency mode and alert the Owner for manual review.
        if author_signature and not settings.get("emergency_mode"):
            restricted = await apply_emergency_mode(context, chat.id, actor_id=0, enabled=True)
            db.log_admin_action(
                chat.id,
                actor_id=0,
                action="emergency_unidentified_admin",
                target_id=None,
                details=(
                    f"Signed post ('{author_signature}') violated a rule ({violation_type}) "
                    "but the responsible admin could not be reliably identified via the Bot API "
                    "(no /setsignature mapping and no live-admin-list name match). Emergency "
                    "mode was auto-activated as a precaution."
                ),
                success=True,
                reason="Unidentifiable signed admin violation — Bot API cannot map signature to user id",
            )
            notice = (
                "HIGH PRIORITY — Unidentified admin violation\n\n"
                f"A signed channel post (signature: \"{author_signature}\") broke a protection "
                f"rule ({violation_type}), but the Bot API could not identify which admin sent "
                "it.\n\nEmergency mode has been activated automatically: every registered "
                "admin's real Telegram rights have been restricted until you review this "
                f"manually.\n\nTo resolve: use /setsignature <user_id> {author_signature}, "
                "then turn emergency mode off from the panel."
            )
            for owner_id in config.owner_ids:
                try:
                    await context.bot.send_message(chat_id=owner_id, text=notice)
                except TelegramError as exc:
                    _mod_log.debug(
                        "Could not send high-priority owner alert to %s: %s", owner_id, exc
                    )
            _mod_log.warning(
                "Auto-activated emergency mode for chat %s: unidentifiable signed admin "
                "violation (signature=%r, violation=%s); restricted admins: %s",
                chat.id, author_signature, violation_type, [a["user_id"] for a in restricted],
            )

        await maybe_auto_trigger_emergency(context, chat, violation_type)
        await send_alert(
            context, chat, violation_type, punishment_label,
            name=author_signature or "Channel post",
            username="not available",
            user_id="not available",
            link="-",
            original_message_id=message_id,
            original_message=original_text or "(not available)",
        )
        return punishment_label

    # Admins are not exempt: if this is a registered (non-restricted) admin,
    # edit their rights down before applying the standard punishment.
    admin_record = db.get_admin(chat.id, target_id)
    if (is_admin_violation or admin_record is not None) and not (
        admin_record and admin_record.get("restricted")
    ):
        if admin_record is not None:
            db.set_admin_restricted(chat.id, target_id, True)
        rights_revoked = await revoke_admin_rights(context, chat.id, target_id)
        db.log_admin_action(
            chat.id,
            actor_id=0,
            action="auto_restrict_violation",
            target_id=target_id,
            details=f"{violation_type} (telegram rights edited to none: {rights_revoked})",
            success=rights_revoked,
            telegram_response="OK" if rights_revoked else "rejected - bot lacks can_promote_members",
            reason=f"Admin violation: {violation_type}",
        )

    try:
        if mode == "delete_warn":
            count = db.add_warning(chat.id, target_id)
            ban_after = settings["ban_after_warnings"]
            punishment_label = f"Warning ({count}/{ban_after})"
            if count >= ban_after:
                await ban_user(context, chat.id, target_id)
                db.increment_stat(chat.id, "banned_count")
                db.reset_warnings(chat.id, target_id)
                punishment_label = "Banned after exceeding warning limit"
        elif mode == "delete_mute":
            await mute_user(context, chat.id, target_id, settings["mute_minutes"])
            db.increment_stat(chat.id, "muted_count")
            punishment_label = f"Muted for {settings['mute_minutes']} minutes"
        elif mode == "delete_ban":
            await ban_user(context, chat.id, target_id)
            db.increment_stat(chat.id, "banned_count")
            punishment_label = "Banned and removed from the channel"
        elif mode == "delete_restrict":
            await restrict_user(context, chat.id, target_id)
            punishment_label = "Restricted"
        else:
            punishment_label = "Deleted only"
    except TelegramError as exc:
        _mod_log.warning("Could not apply punishment in %s for %s: %s", chat.id, target_id, exc)
        punishment_label = f"{punishment_label} (could not apply — missing permissions)"

    if admin_record is not None or is_admin_violation:
        punishment_label += " + admin rights restricted (can no longer post/edit/delete/manage)"

    db.increment_stat(chat.id, "deleted_messages")
    db.log_violation(
        chat_id=chat.id,
        user_id=target_id,
        username=(user.username if user is not None else "") or "",
        full_name=target_name,
        violation_type=violation_type,
        original_text=(original_text or "")[:500],
        punishment=punishment_label,
    )
    await maybe_auto_trigger_emergency(context, chat, violation_type)
    await send_alert(
        context, chat, violation_type, punishment_label,
        name=target_name,
        username=target_username,
        user_id=str(target_id),
        link=f"tg://user?id={target_id}",
        original_message_id=message_id,
        original_message=original_text or "(not available)",
    )
    return punishment_label


# =============================================================================
# 10. INLINE KEYBOARDS
# =============================================================================

def main_menu(chat_title: str | None = None) -> InlineKeyboardMarkup:
    label = f"📢 {chat_title}" if chat_title else "📢 Select chat first"
    rows = [
        [InlineKeyboardButton(label,                    callback_data="panel:select_chat")],
        [InlineKeyboardButton("Protection",             callback_data="panel:protection")],
        [InlineKeyboardButton("Image protection",       callback_data="panel:images")],
        [InlineKeyboardButton("🛑 Forbidden Words",     callback_data="panel:words")],
        [InlineKeyboardButton("🇬🇧 English Protection", callback_data="panel:english")],
        [InlineKeyboardButton("Punishments",            callback_data="panel:punishment")],
        [InlineKeyboardButton("Logs",                   callback_data="panel:logs")],
        [InlineKeyboardButton("Emergency",              callback_data="panel:emergency")],
        [InlineKeyboardButton("Admins",                 callback_data="panel:admins")],
        [InlineKeyboardButton("Stats",                  callback_data="panel:stats")],
        [InlineKeyboardButton("Settings",               callback_data="panel:settings")],
        [InlineKeyboardButton("📋 Managed Chats",       callback_data="panel:chats")],
        [InlineKeyboardButton("Close",                  callback_data="panel:close")],
    ]
    return InlineKeyboardMarkup(rows)


def back_close_row() -> list:
    return [
        InlineKeyboardButton("Back",  callback_data="panel:main"),
        InlineKeyboardButton("Close", callback_data="panel:close"),
    ]


def protection_menu(chat_id: int) -> InlineKeyboardMarkup:
    settings = db.get_settings(chat_id)
    flags = settings["flags"]
    rows = []
    for key, label in PROTECTION_FLAGS.items():
        state = "[ON]" if flags.get(key) else "[OFF]"
        rows.append([InlineKeyboardButton(f"{state} {label}", callback_data=f"flag:{key}")])
    rows.append(back_close_row())
    return InlineKeyboardMarkup(rows)


def image_menu(chat_id: int) -> InlineKeyboardMarkup:
    settings = db.get_settings(chat_id)
    current = settings.get("image_mode", "allow")
    rows = []
    for key, label in IMAGE_MODES.items():
        state = "[X]" if key == current else "[ ]"
        rows.append([InlineKeyboardButton(f"{state} {label}", callback_data=f"image:{key}")])
    rows.append(back_close_row())
    return InlineKeyboardMarkup(rows)


def punishment_menu(chat_id: int) -> InlineKeyboardMarkup:
    settings = db.get_settings(chat_id)
    current = settings["punishment_mode"]
    rows = []
    for key, label in PUNISHMENT_MODES.items():
        state = "[X]" if key == current else "[ ]"
        rows.append([InlineKeyboardButton(f"{state} {label}", callback_data=f"punish:{key}")])
    rows.append(back_close_row())
    return InlineKeyboardMarkup(rows)


def emergency_menu(chat_id: int) -> InlineKeyboardMarkup:
    settings = db.get_settings(chat_id)
    enabled = settings.get("emergency_mode")
    public = settings.get("public_alerts_enabled")
    trigger_count = settings.get("emergency_trigger_count", 0)
    counter = settings.get("emergency_violation_counter", 0)

    emergency_label = (
        "Emergency mode: ON (tap to disable)"
        if enabled
        else "Emergency mode: OFF (tap to enable)"
    )
    public_label = (
        "Public alerts in channel: ON (tap to disable)"
        if public
        else "Public alerts in channel: OFF (tap to enable)"
    )
    auto_label = (
        f"Auto-trigger: {counter}/{trigger_count} violations (tap to change)"
        if trigger_count and trigger_count > 0
        else "Auto-trigger: disabled (tap to set a threshold)"
    )
    rows = [
        [InlineKeyboardButton(emergency_label, callback_data="emergency:toggle")],
        [InlineKeyboardButton(public_label,    callback_data="emergency:toggle_public")],
        [InlineKeyboardButton(auto_label,      callback_data="settings:emergency_trigger_count")],
        back_close_row(),
    ]
    return InlineKeyboardMarkup(rows)


def logs_menu() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("Recent violations",    callback_data="logs:violations")],
        [InlineKeyboardButton("Recent admin actions", callback_data="logs:actions")],
        back_close_row(),
    ]
    return InlineKeyboardMarkup(rows)


def admins_menu() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("View admin list", callback_data="admins:list")],
        back_close_row(),
    ]
    return InlineKeyboardMarkup(rows)


def words_menu(chat_id: int) -> InlineKeyboardMarkup:
    settings = db.get_settings(chat_id)
    enabled = settings.get("forbidden_words_enabled")
    count = len(db.list_forbidden_words(chat_id))
    toggle_label = f"Protection: {'ON' if enabled else 'OFF'} (tap to toggle)"
    rows = [
        [InlineKeyboardButton(toggle_label,                    callback_data="words:toggle")],
        [InlineKeyboardButton(f"View list ({count} words)",    callback_data="words:list")],
        [InlineKeyboardButton("Add word",                      callback_data="words:add")],
        [InlineKeyboardButton("Remove word",                   callback_data="words:remove")],
        [InlineKeyboardButton("Search",                        callback_data="words:search")],
        [InlineKeyboardButton("Import list (paste words)",     callback_data="words:import")],
        [InlineKeyboardButton("Export list",                   callback_data="words:export")],
        back_close_row(),
    ]
    return InlineKeyboardMarkup(rows)


def english_menu(chat_id: int) -> InlineKeyboardMarkup:
    settings = db.get_settings(chat_id)
    current = settings.get("english_mode", "disabled")
    rows = []
    for key, label in ENGLISH_MODES.items():
        state = "[X]" if key == current else "[ ]"
        rows.append([InlineKeyboardButton(f"{state} {label}", callback_data=f"english:{key}")])
    if current == "selected_users":
        users = db.get_english_selected_users(chat_id)
        summary = ", ".join(str(u) for u in users) if users else "none yet"
        rows.append(
            [InlineKeyboardButton(f"Selected users: {summary}", callback_data="english:manage_users")]
        )
    rows.append(back_close_row())
    return InlineKeyboardMarkup(rows)


def settings_menu() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("Change alert chat/channel",          callback_data="settings:alert_chat")],
        [InlineKeyboardButton("Change alert message",               callback_data="settings:alert_template")],
        [InlineKeyboardButton("Change mute duration",               callback_data="settings:mute_minutes")],
        [InlineKeyboardButton("Warnings before ban",                callback_data="settings:ban_after_warnings")],
        [InlineKeyboardButton("Rate-limit thresholds",              callback_data="settings:spam_thresholds")],
        [InlineKeyboardButton("Duplicate content window/threshold", callback_data="settings:duplicate")],
        [InlineKeyboardButton("Auto-emergency violation threshold", callback_data="settings:emergency_trigger_count")],
        back_close_row(),
    ]
    return InlineKeyboardMarkup(rows)


def confirm_close() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("Close", callback_data="panel:close")]])


def managed_chats_menu() -> InlineKeyboardMarkup:
    """Lists the allowed chats with remove and add controls."""
    chats = db.list_managed_chats()
    rows = []
    for chat in chats:
        title = chat.get("title") or str(chat["chat_id"])
        rows.append([
            InlineKeyboardButton(
                f"Remove {title} ({chat['chat_id']})",
                callback_data=f"chats:remove:{chat['chat_id']}",
            )
        ])
    rows.append([InlineKeyboardButton("Add allowed channel / group", callback_data="chats:add")])
    rows.append(back_close_row())
    return InlineKeyboardMarkup(rows)


def chat_selector_menu() -> InlineKeyboardMarkup:
    """Shown when the owner has multiple managed chats and needs to pick one to configure."""
    chats = db.list_managed_chats()
    rows = []
    for chat in chats:
        title = chat.get("title") or str(chat["chat_id"])
        rows.append([
            InlineKeyboardButton(
                f"📢 {title}",
                callback_data=f"chats:select:{chat['chat_id']}",
            )
        ])
    rows.append([InlineKeyboardButton("Close", callback_data="panel:close")])
    return InlineKeyboardMarkup(rows)


async def _show_managed_chats(query) -> None:
    """Render the allowed-chats screen, with a fallback for non-editable messages."""
    text = (
        "*Allowed channels and groups*\n\n"
        "The bot protects every chat listed below. Select a chat to remove it, "
        "or add a new channel/group using its numeric ID.\n\n"
        "The bot must already be an administrator in a chat before it can protect it."
    )
    try:
        await query.edit_message_text(
            text,
            parse_mode="Markdown",
            reply_markup=managed_chats_menu(),
        )
    except TelegramError:
        # A callback can originate from an old or non-editable message. The
        # control must still open instead of silently failing.
        await query.message.reply_text(
            text,
            parse_mode="Markdown",
            reply_markup=managed_chats_menu(),
        )


# =============================================================================
# 11. HANDLERS: /start and /help
# =============================================================================

HELP_TEXT = (
    "*Advanced Channel Protection Bot*\n\n"
    "Add the bot as an admin in your channel and grant it permission to delete messages "
    "and ban members. This bot works exclusively with channels, not groups.\n\n"
    "Since Telegram does not expose the identity of the publisher inside the channel, "
    "all commands are managed from a private chat with the bot and target the "
    "pre-configured protected channel.\n\n"
    "*Available commands (private chat only):*\n"
    "/panel — control panel\n"
    "/settings — settings\n"
    "/stats — statistics\n"
    "/logs — logs\n"
    "/emergency — toggle emergency mode\n"
    "/admins — admin list\n"
    "/promote `<user_id>` — add an admin (posting-only by default)\n"
    "/demote `<user_id>` — remove an admin entirely\n"
    "/restrict `<user_id>` — disable an admin's posting/edit/delete/manage rights (keeps them listed)\n"
    "/unrestrict `<user_id>` — lift a restriction, restoring their configured rights\n"
    "/setright `<user_id> <right> <on|off>` — grant/revoke one specific right\n"
    "/rights `<user_id>` — show an admin's current rights and status\n"
    "/setsignature `<user_id> <signature>` — map a channel signature to an admin\n"
    "/ban `<user_id>` — ban a member\n"
    "/unban `<user_id>` — unban a member\n"
    "/mute `<user_id> [minutes]` — mute a member\n"
    "/unmute `<user_id>` — unmute a member\n"
    "/warn `<user_id>` — warn a member\n"
    "/unwarn `<user_id>` — clear warnings\n\n"
    "*Protection modules (configure from /panel):*\n"
    "🛑 Forbidden Words — a custom, editable word blacklist.\n"
    "🇬🇧 English Messages Protection — delete/allow English-letter messages by mode.\n"
    "Phone/contact number blocking and an advanced link/invite detector are toggles "
    "inside Protection settings.\n"
)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat.type == "private":
        await update.effective_message.reply_text(
            "Welcome.\nAdd me as an admin in your channel to enable advanced protection.\n"
            "Use /help to see the available commands (all used here, in this private chat)."
        )
        return
    if chat.type == "channel" and config.allowed_chat_id and chat.id == config.allowed_chat_id:
        db.ensure_group(chat.id, chat.title or str(chat.id))
        await update.effective_message.reply_text("Protection has been enabled for this channel.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(HELP_TEXT, parse_mode="Markdown")


async def track_new_group(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat and chat.type == "channel":
        db.ensure_group(chat.id, chat.title or str(chat.id))


# =============================================================================
# 12. HANDLERS: /stats
# =============================================================================

def format_stats_text(chat_id: int, stats: dict, top_user_name: str | None) -> str:
    lines = [
        "*Protection statistics*\n",
        f"Deleted messages: {stats['deleted_messages']}",
        f"Edit attempts: {stats['edit_attempts']}",
        f"GIFs deleted: {stats['gifs_deleted']}",
        f"Banned: {stats['banned_count']}",
        f"Muted: {stats['muted_count']}",
        f"Warnings: {stats['warnings_count']}",
    ]
    if top_user_name:
        lines.append(f"Most frequent offender: {top_user_name}")
    return "\n".join(lines)


@require_admin_or_owner
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    stats = db.get_stats(chat_id)
    top = db.get_most_violating_user(chat_id)
    top_name = None
    if top:
        user_id, count = top
        top_name = f"`{user_id}` ({count} violations)"
    await update.effective_message.reply_text(
        format_stats_text(chat_id, stats, top_name), parse_mode="Markdown"
    )


# =============================================================================
# 13. HANDLERS: admin management
# =============================================================================

def _admin_target_id(context: ContextTypes.DEFAULT_TYPE) -> int | None:
    if context.args and context.args[0].lstrip("-").isdigit():
        return int(context.args[0])
    return None


def _rights_summary(rights: dict) -> str:
    granted = [label for key, label in TELEGRAM_RIGHTS.items() if rights.get(key)]
    return ", ".join(granted) if granted else "none (fully restricted)"


@require_owner
async def promote_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Promotes a user to admin (posting-only by default). Use /setright to grant more."""
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _admin_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text(
            "Usage: /promote <user_id>\nSend this command in a private chat with the bot."
        )
        return
    all_perms = list(ADMIN_PERMISSIONS.keys())
    rights = dict(DEFAULT_TELEGRAM_RIGHTS)
    db.add_admin(chat_id, target_id, all_perms, added_by=update.effective_user.id,
                 telegram_rights=rights)

    applied = await apply_admin_rights(context, chat_id, target_id, rights)
    db.log_admin_action(
        chat_id, update.effective_user.id, "promote", target_id,
        f"telegram rights applied (post-only default): {applied}",
    )

    if applied:
        await update.effective_message.reply_text(
            f"`{target_id}` is now an admin — granted *posting only* on the channel itself "
            "(cannot edit, delete, invite, manage, restrict, or promote). "
            "Use /setright to change this.",
            parse_mode="Markdown",
        )
    else:
        bot_rights = await check_bot_admin_rights(context, chat_id)
        missing = [r for r, ok in bot_rights.items() if not ok]
        await update.effective_message.reply_text(
            f"`{target_id}` was added to the bot's admin list, but Telegram REJECTED the real "
            "promotion — the bot itself is missing required rights in the channel: "
            f"`{', '.join(missing) or 'can_promote_members'}`.\n\n"
            "Fix: open the channel → Administrators → this bot's admin rights, and enable "
            "'Add New Admins', 'Delete Messages', and 'Ban/restrict Users'.",
            parse_mode="Markdown",
        )


@require_owner
async def demote_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _admin_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text(
            "Usage: /demote <user_id>\nSend this command in a private chat with the bot."
        )
        return
    db.remove_admin(chat_id, target_id)
    db.log_admin_action(chat_id, update.effective_user.id, "demote", target_id)
    await update.effective_message.reply_text(
        f"`{target_id}` has been removed from admins.", parse_mode="Markdown"
    )


@require_owner
async def restrict_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Restricts an admin's rights without removing them from the list (reversible)."""
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _admin_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text(
            "Usage: /restrict <user_id>\nSend this command in a private chat with the bot."
        )
        return
    admin = db.get_admin(chat_id, target_id)
    if admin is None:
        await update.effective_message.reply_text("That user is not a registered admin.")
        return
    db.set_admin_restricted(chat_id, target_id, True)
    revoked = await revoke_admin_rights(context, chat_id, target_id)
    db.log_admin_action(
        chat_id, update.effective_user.id, "manual_restrict", target_id,
        f"telegram rights edited to none: {revoked}",
    )
    if revoked:
        await update.effective_message.reply_text(
            f"`{target_id}` is now restricted — they can no longer post, edit, delete, or manage "
            "anything, but remain listed as an admin. Use /unrestrict to lift this.",
            parse_mode="Markdown",
        )
    else:
        await update.effective_message.reply_text(
            f"`{target_id}` is flagged restricted in the bot's records, but Telegram REJECTED "
            "the rights change — the bot itself lacks 'can_promote_members' in this channel.",
            parse_mode="Markdown",
        )


@require_owner
async def unrestrict_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _admin_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text(
            "Usage: /unrestrict <user_id>\nSend this command in a private chat with the bot."
        )
        return
    admin = db.get_admin(chat_id, target_id)
    if admin is None:
        await update.effective_message.reply_text("That user is not a registered admin.")
        return
    db.set_admin_restricted(chat_id, target_id, False)
    applied = await apply_admin_rights(context, chat_id, target_id, admin["telegram_rights"])
    db.log_admin_action(
        chat_id, update.effective_user.id, "manual_unrestrict", target_id,
        f"stored telegram rights re-applied: {applied}",
    )
    await update.effective_message.reply_text(
        f"`{target_id}` is no longer restricted. Rights restored to: "
        f"{_rights_summary(admin['telegram_rights'])}.",
        parse_mode="Markdown",
    )


@require_owner
async def setright_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Toggles ONE specific Telegram right for an already-promoted admin.
    Usage: /setright <user_id> <right> <on|off>"""
    chat_id = _target_chat_id(update.effective_user.id)
    if len(context.args) < 3 or not context.args[0].lstrip("-").isdigit():
        keys = "\n".join(f"- `{k}` — {v}" for k, v in TELEGRAM_RIGHTS.items())
        await update.effective_message.reply_text(
            "Usage: /setright <user_id> <right> <on|off>\n\nAvailable rights:\n" + keys,
            parse_mode="Markdown",
        )
        return
    target_id = int(context.args[0])
    right = context.args[1].strip()
    value_raw = context.args[2].strip().lower()
    if right not in TELEGRAM_RIGHTS:
        await update.effective_message.reply_text(
            f"Unknown right `{right}`. See /setright with no arguments for the full list.",
            parse_mode="Markdown",
        )
        return
    if value_raw not in ("on", "off"):
        await update.effective_message.reply_text(
            "Value must be `on` or `off`.", parse_mode="Markdown"
        )
        return
    value = value_raw == "on"
    admin = db.get_admin(chat_id, target_id)
    if admin is None:
        await update.effective_message.reply_text(
            "That user is not a registered admin. Use /promote first."
        )
        return
    rights = db.set_admin_telegram_right(chat_id, target_id, right, value)
    if admin.get("restricted"):
        await update.effective_message.reply_text(
            f"Saved: `{right}` = `{value_raw}` for `{target_id}`.\n"
            "They are currently restricted; this will take effect on Telegram once unrestricted. "
            f"Stored rights are now: {_rights_summary(rights)}",
            parse_mode="Markdown",
        )
        db.log_admin_action(
            chat_id, update.effective_user.id, "setright_pending", target_id, f"{right}={value_raw}"
        )
        return
    applied = await apply_admin_rights(context, chat_id, target_id, rights)
    db.log_admin_action(
        chat_id, update.effective_user.id, "setright", target_id,
        f"{right}={value_raw} (applied: {applied})",
    )
    if applied:
        await update.effective_message.reply_text(
            f"`{target_id}`'s Telegram rights updated. `{right}` = `{value_raw}`.\n"
            f"Current rights: {_rights_summary(rights)}",
            parse_mode="Markdown",
        )
    else:
        await update.effective_message.reply_text(
            f"Saved `{right}` = `{value_raw}` in the bot's records, but Telegram REJECTED "
            "applying it — the bot itself lacks 'can_promote_members' in this channel.",
            parse_mode="Markdown",
        )


@require_admin_or_owner
async def rights_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _admin_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /rights <user_id>")
        return
    admin = db.get_admin(chat_id, target_id)
    if admin is None:
        await update.effective_message.reply_text("That user is not a registered admin.")
        return
    status = "RESTRICTED (all rights suspended)" if admin.get("restricted") else "active"
    await update.effective_message.reply_text(
        f"Admin `{target_id}` — status: {status}\n"
        f"Configured rights: {_rights_summary(admin['telegram_rights'])}",
        parse_mode="Markdown",
    )


@require_owner
async def setsignature_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    if not context.args or not context.args[0].lstrip("-").isdigit() or len(context.args) < 2:
        await update.effective_message.reply_text(
            "Usage: /setsignature <user_id> <signature text>\n"
            "The signature text must match exactly what this admin sets as their "
            "channel post signature (Channel settings → Sign messages)."
        )
        return
    target_id = int(context.args[0])
    signature = " ".join(context.args[1:]).strip()
    admin = db.get_admin(chat_id, target_id)
    if admin is None:
        await update.effective_message.reply_text(
            "That user is not registered as an admin yet. Use /promote first."
        )
        return
    db.set_admin_signature(chat_id, target_id, signature)
    db.log_admin_action(chat_id, update.effective_user.id, "set_signature", target_id, signature)
    await update.effective_message.reply_text(
        f"Signature for `{target_id}` set to: {signature}\n"
        "Violations posted under this signature will now be attributed to this admin.",
        parse_mode="Markdown",
    )


@require_admin_or_owner
async def admins_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    admins = db.list_admins(chat_id)
    lines = ["*Admin list:*\n"]
    if not admins:
        lines.append("No admins added yet.")
    for admin in admins:
        sig = f" (signature: {admin['signature']})" if admin.get("signature") else ""
        flag = " — RESTRICTED" if admin.get("restricted") else ""
        rights = _rights_summary(admin.get("telegram_rights") or {})
        lines.append(f"- `{admin['user_id']}`{sig}{flag}\n  rights: {rights}")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


# =============================================================================
# 14. HANDLERS: manual moderation commands
# =============================================================================

def _mod_target_id(context: ContextTypes.DEFAULT_TYPE) -> int | None:
    if context.args and context.args[0].lstrip("-").isdigit():
        return int(context.args[0])
    return None


@require_permission("ban_members")
async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _mod_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /ban <user_id>")
        return
    await ban_user(context, chat_id, target_id)
    db.increment_stat(chat_id, "banned_count")
    db.log_admin_action(chat_id, update.effective_user.id, "ban", target_id)
    await update.effective_message.reply_text(
        f"`{target_id}` has been banned.", parse_mode="Markdown"
    )


@require_permission("ban_members")
async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _mod_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /unban <user_id>")
        return
    await unban_user(context, chat_id, target_id)
    db.log_admin_action(chat_id, update.effective_user.id, "unban", target_id)
    await update.effective_message.reply_text("The ban has been lifted.")


@require_permission("mute_members")
async def mute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _mod_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /mute <user_id> [minutes]")
        return
    settings = db.get_settings(chat_id)
    minutes = settings["mute_minutes"]
    if len(context.args) > 1 and context.args[1].isdigit():
        minutes = int(context.args[1])
    await mute_user(context, chat_id, target_id, minutes)
    db.increment_stat(chat_id, "muted_count")
    db.log_admin_action(
        chat_id, update.effective_user.id, "mute", target_id, f"{minutes} minutes"
    )
    await update.effective_message.reply_text(
        f"`{target_id}` has been muted for {minutes} minutes.", parse_mode="Markdown"
    )


@require_permission("unmute_members")
async def unmute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _mod_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /unmute <user_id>")
        return
    await unmute_user(context, chat_id, target_id)
    db.log_admin_action(chat_id, update.effective_user.id, "unmute", target_id)
    await update.effective_message.reply_text(
        f"`{target_id}` has been unmuted.", parse_mode="Markdown"
    )


@require_permission("delete_messages")
async def warn_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _mod_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /warn <user_id>")
        return
    count = db.add_warning(chat_id, target_id)
    db.log_admin_action(chat_id, update.effective_user.id, "warn", target_id)
    settings = db.get_settings(chat_id)
    ban_after = settings["ban_after_warnings"]
    if count >= ban_after:
        await ban_user(context, chat_id, target_id)
        db.increment_stat(chat_id, "banned_count")
        db.reset_warnings(chat_id, target_id)
        await update.effective_message.reply_text(
            f"`{target_id}` exceeded the warning limit and has been banned.",
            parse_mode="Markdown",
        )
    else:
        await update.effective_message.reply_text(
            f"`{target_id}` has been warned ({count}/{ban_after}).", parse_mode="Markdown"
        )


@require_permission("delete_messages")
async def unwarn_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = _target_chat_id(update.effective_user.id)
    target_id = _mod_target_id(context)
    if target_id is None:
        await update.effective_message.reply_text("Usage: /unwarn <user_id>")
        return
    db.reset_warnings(chat_id, target_id)
    db.log_admin_action(chat_id, update.effective_user.id, "unwarn", target_id)
    await update.effective_message.reply_text(
        f"Warnings cleared for `{target_id}`.", parse_mode="Markdown"
    )


# =============================================================================
# 15. HANDLERS: /emergency
# =============================================================================

@require_owner
async def emergency_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Quick toggle for emergency mode from a private chat."""
    chat_id = _target_chat_id(update.effective_user.id)
    settings = db.get_settings(chat_id)
    new_state = not settings.get("emergency_mode")
    db.log_admin_action(
        chat_id, update.effective_user.id, "toggle_emergency", None, str(new_state)
    )
    affected = await apply_emergency_mode(context, chat_id, update.effective_user.id, new_state)

    status = "enabled" if new_state else "disabled"
    text = f"Emergency mode {status}."
    if new_state and affected:
        ids = ", ".join(str(a["user_id"]) for a in affected)
        text += (
            f"\nAll admins have been restricted ({ids}) — they can no longer post, edit, "
            "delete, or manage anything; only the Owner has full access now."
        )
    elif not new_state and affected:
        ids = ", ".join(str(a["user_id"]) for a in affected)
        text += f"\nAdmin status restored for: {ids}."

    if new_state:
        bot_rights = await check_bot_admin_rights(context, chat_id)
        missing = [r for r, ok in bot_rights.items() if not ok]
        if missing:
            text += (
                "\n\n⚠️ WARNING: the bot itself is missing required rights in the channel "
                f"({', '.join(missing)}) — the restriction was saved in the bot's records "
                "but Telegram REJECTED the real rights change. Fix this in the channel's "
                "Administrators settings: give the bot 'Add New Admins', 'Delete Messages', "
                "and 'Ban Users' rights."
            )
    await update.effective_message.reply_text(text)


# =============================================================================
# 16. HANDLERS: protection engine
# =============================================================================

_prot_log = get_logger("protection")

# Cache of channel admin lists to avoid hammering the API
_ADMIN_CACHE: dict[int, tuple[float, list]] = {}
_ADMIN_CACHE_TTL_SECONDS = 300


async def _get_channel_administrators(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    """Best-effort, TTL-cached fetch of the channel's real Telegram admin list."""
    cached = _ADMIN_CACHE.get(chat_id)
    now = time.time()
    if cached and now - cached[0] < _ADMIN_CACHE_TTL_SECONDS:
        return cached[1]
    try:
        admins = await context.bot.get_chat_administrators(chat_id)
    except TelegramError as exc:
        _prot_log.debug("Could not fetch channel administrators for %s: %s", chat_id, exc)
        return cached[1] if cached else []
    _ADMIN_CACHE[chat_id] = (now, admins)
    return admins


async def _resolve_identity(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, author_signature: str | None
):
    """Returns (resolved_user_id, resolved_name) for a channel post author.

    Priority:
      1. Explicit /setsignature mapping (authoritative).
      2. Best-effort name match against the live channel admin list.
      3. (None, None) if neither resolves — a hard Bot API limitation.
    """
    if not author_signature:
        return None, None

    admin = db.get_admin_by_signature(chat_id, author_signature)
    if admin is not None:
        return admin["user_id"], author_signature

    sig_norm = author_signature.strip().lower()
    if not sig_norm:
        return None, None
    tg_admins = await _get_channel_administrators(context, chat_id)
    for member in tg_admins:
        candidates = [
            member.user.full_name,
            member.user.first_name,
            member.user.username,
            getattr(member, "custom_title", None),
        ]
        if any(c and c.strip().lower() == sig_norm for c in candidates):
            if db.get_admin(chat_id, member.user.id) is not None:
                return member.user.id, author_signature
    return None, None


async def _actor_is_owner(chat_id: int, user, resolved_id: int | None) -> bool:
    if user is not None and db.is_owner(user.id):
        return True
    if resolved_id is not None and db.is_owner(resolved_id):
        return True
    return False


def _actor_is_admin(chat_id: int, user, resolved_id: int | None) -> bool:
    """True only for an active (non-restricted) admin."""
    admin = None
    if user is not None:
        admin = db.get_admin(chat_id, user.id)
    if admin is None and resolved_id is not None:
        admin = db.get_admin(chat_id, resolved_id)
    return admin is not None and not admin.get("restricted")


async def handle_new_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Core protection engine — fires on every new channel post."""
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if message is None or chat is None:
        return

    db.ensure_group(chat.id, chat.title or str(chat.id))
    settings = db.get_settings(chat.id)
    flags = settings["flags"]

    sig = media_signature(message)
    db.cache_message(
        chat.id, message.message_id,
        user.id if user else 0,
        sig,
        message.text or message.caption,
    )

    author_signature = getattr(message, "author_signature", None)
    resolved_id, resolved_name = await _resolve_identity(context, chat.id, author_signature)

    # Only the Owner is exempt from protection rules
    if await _actor_is_owner(chat.id, user, resolved_id):
        return

    is_admin_actor = _actor_is_admin(chat.id, user, resolved_id)
    text = message.text or message.caption or ""

    async def punish(violation: str):
        await enforce_punishment(
            context, chat, user, violation, text, message.message_id,
            author_signature=author_signature,
            resolved_user_id=resolved_id,
            resolved_name=resolved_name,
            is_admin_violation=is_admin_actor,
        )

    # 1. Empty messages
    if flags.get("block_empty") and is_empty_message(message):
        await punish("Empty message")
        return

    # 2. Image protection
    if message.photo:
        image_mode = settings.get("image_mode", "allow")
        if image_mode == "block_all":
            await punish("Unauthorized image")
            return
        if image_mode == "admins_only" and not is_admin_actor:
            await punish("Image (admins only)")
            return

    # 3. GIF / animation
    if flags.get("block_gif") and message.animation:
        await punish("Sent a GIF")
        db.increment_stat(chat.id, "gifs_deleted")
        return

    # 4. Stickers
    if flags.get("block_stickers") and message.sticker:
        await punish("Sent a sticker")
        return

    # 5. Circular video (video note)
    if flags.get("block_video_note") and message.video_note:
        await punish("Video note")
        return

    # 6. Voice messages
    if flags.get("block_voice") and message.voice:
        await punish("Voice message")
        return

    # 7. Video messages
    if flags.get("block_video") and message.video:
        await punish("Video message")
        return

    # 8. Documents / files
    if flags.get("block_document") and message.document:
        await punish("File")
        return

    # 9. Polls
    if flags.get("block_poll") and message.poll:
        await punish("Poll")
        return

    # 10. Games
    if flags.get("block_game") and message.game:
        await punish("Game")
        return

    # 11. Contacts
    if flags.get("block_contact") and message.contact:
        await punish("Contact")
        return

    # 12. Locations / venues
    if flags.get("block_location") and (message.location or message.venue):
        await punish("Location")
        return

    # 13. Links (robust engine: http(s), www, t.me, Discord invites,
    #     Markdown/HTML hyperlinks, obfuscated dots, generic <text>.<tld>)
    if flags.get("block_links") and contains_link(text):
        if not flags.get("links_admins_only") or not is_admin_actor:
            await punish("Forbidden link")
            return

    # 13b. Phone / contact numbers
    if flags.get("block_phone_numbers") and contains_phone_number(text):
        await punish("Phone/contact number")
        return

    # 13c. Forbidden words (custom blacklist, case-insensitive, whole-word)
    if settings.get("forbidden_words_enabled"):
        words = db.list_forbidden_words(chat.id)
        matched = find_forbidden_word(text, words)
        if matched:
            await punish(f"Forbidden word ({matched})")
            return

    # 13d. English-language message protection
    english_mode = settings.get("english_mode", "disabled")
    if english_mode != "disabled" and contains_english(text):
        exempt = False
        if english_mode == "admins_only":
            exempt = is_admin_actor
        elif english_mode == "selected_users":
            actor_id = resolved_id if resolved_id is not None else (user.id if user else None)
            exempt = actor_id is not None and actor_id in db.get_english_selected_users(chat.id)
        # "delete_all" → never exempt
        if not exempt:
            await punish("English-language message")
            return

    # 14. Mass mentions
    if flags.get("anti_mass_mention") and is_mass_mention(text):
        await punish("Mass mention")
        return

    # 15. Spammy hashtags
    if flags.get("anti_spam_hashtags") and is_spammy_hashtags(text):
        await punish("Spammy hashtags")
        return

    # 16. Duplicate / repeated content
    dup_id = resolved_id if resolved_id is not None else (user.id if user else None)
    if dup_id is not None and flags.get("anti_duplicate"):
        c_sig = content_signature(message)
        if c_sig and is_duplicate_content(
            chat.id, dup_id, c_sig,
            settings.get("duplicate_window_seconds", DEFAULT_DUPLICATE_WINDOW_SECONDS),
            settings.get("duplicate_repeat_threshold", DEFAULT_DUPLICATE_REPEAT_THRESHOLD),
        ):
            await punish("Duplicate/repeated content (spam)")
            return

    # 17. Rate-limit / flood detection
    flood_id = resolved_id if resolved_id is not None else (user.id if user else None)
    if flood_id is not None and flags.get("anti_flood"):
        thresholds = settings.get("spam_thresholds") or DEFAULT_SPAM_THRESHOLDS
        burst_ids = check_flood(chat.id, flood_id, message.message_id, thresholds)
        if burst_ids is not None:
            for mid in burst_ids:
                if mid != message.message_id:
                    await delete_message_safe(context, chat.id, mid)
            await punish("Rate limit exceeded (spam)")
            return


async def handle_edited_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Fires on every edited channel post."""
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if message is None or chat is None:
        return

    db.ensure_group(chat.id, chat.title or str(chat.id))
    settings = db.get_settings(chat.id)
    flags = settings["flags"]

    author_signature = getattr(message, "author_signature", None)
    resolved_id, resolved_name = await _resolve_identity(context, chat.id, author_signature)

    if await _actor_is_owner(chat.id, user, resolved_id):
        return

    is_admin_actor = _actor_is_admin(chat.id, user, resolved_id)
    cached = db.get_cached_message(chat.id, message.message_id)
    is_media = bool(
        message.photo or message.video or message.document or message.audio
        or message.voice or message.video_note or message.animation
    )

    db.increment_stat(chat.id, "edit_attempts")

    if is_media and flags.get("block_edited_media"):
        await enforce_punishment(
            context, chat, user, "Edited/replaced media",
            message.caption or "", message.message_id,
            author_signature=author_signature,
            resolved_user_id=resolved_id,
            resolved_name=resolved_name,
            is_admin_violation=is_admin_actor,
        )
        return

    if not is_media and flags.get("block_edited_text"):
        original = cached["text"] if cached else ""
        await enforce_punishment(
            context, chat, user, "Edited text message",
            f"Original: {original}\nEdited: {message.text or ''}",
            message.message_id,
            author_signature=author_signature,
            resolved_user_id=resolved_id,
            resolved_name=resolved_name,
            is_admin_violation=is_admin_actor,
        )
        return


# =============================================================================
# 17. HANDLERS: control panel
# =============================================================================

_panel_log = get_logger("panel")

# Per-user pending text-input state: {(chat_id, user_id): field_name}
_PENDING_INPUT: dict[tuple[int, int], str] = {}

# Per-owner selected chat context for the panel: {owner_user_id: chat_id}
# Lets the owner configure different managed chats from the same private chat.
_PANEL_CONTEXT: dict[int, int] = {}


def _target_chat_id(user_id: int | None = None) -> int | None:
    """Returns the chat_id the panel should target for a given owner/user.

    Priority:
      1. Chat the owner explicitly selected via the panel chat-picker.
      2. The only managed chat (if exactly one exists).
      3. config.allowed_chat_id as a last-resort fallback.
    """
    if user_id is not None and user_id in _PANEL_CONTEXT:
        return _PANEL_CONTEXT[user_id]
    managed = db.list_managed_chats()
    if len(managed) == 1:
        return managed[0]["chat_id"]
    if managed:
        # Multiple chats: no unambiguous default — caller must pick one.
        return None
    return config.allowed_chat_id


async def _replace_message(query, text: str, reply_markup=None, parse_mode: str | None = "Markdown"):
    """Update the current panel message without creating duplicate outputs."""
    try:
        await query.edit_message_text(
            text,
            parse_mode=parse_mode,
            reply_markup=reply_markup,
        )
    except TelegramError:
        # Some old Telegram messages cannot be edited. Only in that case do
        # we create a replacement message; normal panel navigation never
        # deletes and re-sends the same output.
        await query.message.get_bot().send_message(
            chat_id=query.message.chat_id,
            text=text,
            parse_mode=parse_mode,
            reply_markup=reply_markup,
        )


def _wrap_rows(rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(rows)


def _violations_text(chat_id: int) -> str:
    rows = db.get_recent_violations(chat_id)
    if not rows:
        return "No violations recorded yet."
    lines = ["*Recent violations:*\n"]
    for row in rows:
        name = row["full_name"] or row["username"] or str(row["user_id"])
        lines.append(f"- {name} — {row['violation_type']} — {row['punishment']}")
    return "\n".join(lines)


def _actions_text(chat_id: int) -> str:
    rows = db.get_recent_admin_actions(chat_id)
    if not rows:
        return "No admin actions recorded yet."
    lines = ["*Recent admin actions:*\n"]
    for row in rows:
        status = ""
        if row.get("success") is not None:
            status = " [OK]" if row["success"] else " [FAILED]"
        reason = f" — {row['reason']}" if row.get("reason") else ""
        lines.append(f"- Action: {row['action']} — Target: {row['target_id']}{status}{reason}")
    return "\n".join(lines)


def _parse_thresholds(text: str) -> list[list[int]] | None:
    pairs = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            return None
        count_str, window_str = chunk.split(":", 1)
        if not count_str.strip().isdigit() or not window_str.strip().isdigit():
            return None
        pairs.append([int(count_str.strip()), int(window_str.strip())])
    return pairs or None


async def panel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    managed = db.list_managed_chats()

    # Owner: show chat selector if no context yet and multiple chats exist
    if db.is_owner(user.id):
        chat_id = _target_chat_id(user.id)
        if chat_id is None and len(managed) > 1:
            await update.effective_message.reply_text(
                "*Protection Control Panel*\n\nYou have multiple managed chats. "
                "Which one would you like to configure?",
                parse_mode="Markdown",
                reply_markup=chat_selector_menu(),
            )
            return
        if chat_id is None and len(managed) == 0:
            await update.effective_message.reply_text(
                "No chats are managed yet.\n\n"
                "Use the button below to add the first channel or group. "
                "You need to add the bot as an admin in that chat first.\n\n"
                "Send the chat ID now, or open the Managed Chats menu:",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("📋 Managed Chats", callback_data="panel:chats")],
                    [InlineKeyboardButton("Close", callback_data="panel:close")],
                ]),
            )
            return
        if chat_id is None and len(managed) == 1:
            chat_id = managed[0]["chat_id"]
            _PANEL_CONTEXT[user.id] = chat_id
    else:
        chat_id = _target_chat_id(user.id)
        if chat_id is None:
            await update.effective_message.reply_text(
                "No protected chat is configured yet."
            )
            return
        if not is_group_admin_or_owner(chat_id, user.id):
            await update.effective_message.reply_text(
                "The control panel is restricted to admins and the owner."
            )
            return

    db.ensure_group(chat_id, str(chat_id))
    chat_info = db.get_managed_chat(chat_id)
    chat_title = (chat_info.get("title") if chat_info else None) or str(chat_id)
    await update.effective_message.reply_text(
        "*Protection Control Panel*\nChoose a section:",
        parse_mode="Markdown",
        reply_markup=main_menu(chat_title),
    )


async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await panel_command(update, context)


async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    chat_id = _target_chat_id(user.id)
    if chat_id is None or not is_group_admin_or_owner(chat_id, user.id):
        await update.effective_message.reply_text(
            "This command is restricted to admins and the owner. "
            "Use /panel to select a chat first."
        )
        return
    await update.effective_message.reply_text("Choose a log type:", reply_markup=logs_menu())


async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Routes all inline keyboard callbacks."""
    query = update.callback_query
    user = update.effective_user
    await query.answer()

    data = query.data or ""

    # ---- Managed-chats: chat selector (owner only, before chat_id is resolved) ----
    if data.startswith("chats:select:"):
        if not db.is_owner(user.id):
            await query.message.reply_text("Owner only.")
            return
        selected_id = int(data.split(":", 2)[2])
        _PANEL_CONTEXT[user.id] = selected_id
        chat_info = db.get_managed_chat(selected_id)
        chat_title = (chat_info.get("title") if chat_info else None) or str(selected_id)
        await query.edit_message_text(
            f"*Protection Control Panel*\nConfiguring: *{chat_title}*\nChoose a section:",
            parse_mode="Markdown",
            reply_markup=main_menu(chat_title),
        )
        return

    # ---- panel:select_chat — re-open the chat picker ----
    if data == "panel:select_chat":
        if not db.is_owner(user.id):
            await query.message.reply_text("Owner only.")
            return
        managed = db.list_managed_chats()
        if len(managed) <= 1:
            await query.message.reply_text("Only one managed chat — no need to switch.")
            return
        await query.edit_message_text(
            "*Select a chat to configure:*",
            parse_mode="Markdown",
            reply_markup=chat_selector_menu(),
        )
        return

    # Resolve the target chat for the rest of the callbacks
    chat_id = _target_chat_id(user.id)

    # ---- Allowed-chats panel (owner only, no chat context required) ----
    if data in {"panel:chats", "panel:allowed_chats"}:
        if not db.is_owner(user.id):
            await query.message.reply_text("Owner only.")
            return
        await _show_managed_chats(query)
        return

    if data == "chats:add":
        if not db.is_owner(user.id):
            await query.message.reply_text("Owner only.")
            return
        # Use a special pending-input key that does not depend on chat_id
        _PENDING_INPUT[(-1, user.id)] = "add_chat"
        await query.message.reply_text(
            "Send the numeric ID of the channel or group to add.\n\n"
            "⚠️ Make sure the bot is already an *admin* in that chat before adding it, "
            "otherwise it won't be able to delete messages or ban members.\n\n"
            "Example: `-1001234567890`",
            parse_mode="Markdown",
        )
        return

    if data.startswith("chats:remove:"):
        if not db.is_owner(user.id):
            await query.message.reply_text("Owner only.")
            return
        remove_id = int(data.split(":", 2)[2])
        chat_info = db.get_managed_chat(remove_id)
        removed = db.remove_managed_chat(remove_id)
        # Clear panel context if the removed chat was selected
        if _PANEL_CONTEXT.get(user.id) == remove_id:
            _PANEL_CONTEXT.pop(user.id, None)
        title = (chat_info.get("title") if chat_info else None) or str(remove_id)
        # The callback was already acknowledged once at the top of this
        # function. Put the status in the edited panel instead of trying to
        # acknowledge the same callback a second time.
        await query.edit_message_text(
            f"*Allowed channels and groups*\n\n"
            f"{'Removed: ' + title if removed else 'That chat was not in the list.'}\n\n"
            "Select a chat to remove it, or add a new one:",
            parse_mode="Markdown",
            reply_markup=managed_chats_menu(),
        )
        return

    # All remaining callbacks require a resolved chat_id
    if chat_id is None or not is_group_admin_or_owner(chat_id, user.id):
        await query.message.reply_text(
            "No chat selected or access denied. Use /panel to pick a chat first."
        )
        return

    # ---- Navigation ----
    if data == "panel:close":
        await query.message.delete()
        return

    chat_info = db.get_managed_chat(chat_id)
    chat_title = (chat_info.get("title") if chat_info else None) or str(chat_id)

    if data == "panel:main":
        await query.edit_message_text(
            f"*Protection Control Panel*\nConfiguring: *{chat_title}*\nChoose a section:",
            parse_mode="Markdown",
            reply_markup=main_menu(chat_title),
        )
        return

    if data == "panel:protection":
        await query.edit_message_text(
            "*Protection settings*\nTap to toggle each option:",
            parse_mode="Markdown",
            reply_markup=protection_menu(chat_id),
        )
        return

    if data == "panel:images":
        await query.edit_message_text(
            "*Image protection*\nChoose how images are handled in the channel:",
            parse_mode="Markdown",
            reply_markup=image_menu(chat_id),
        )
        return

    if data == "panel:punishment":
        await query.edit_message_text(
            "*Choose the default punishment type:*",
            parse_mode="Markdown",
            reply_markup=punishment_menu(chat_id),
        )
        return

    if data == "panel:emergency":
        await query.edit_message_text(
            "*Emergency mode*\nWhen enabled, all admins are alerted immediately for any "
            "violation with full details. Violation alerts always go privately to the Owner "
            "and admins; public alerts (posted in the channel itself) are a separate, "
            "opt-in toggle below.",
            parse_mode="Markdown",
            reply_markup=emergency_menu(chat_id),
        )
        return

    if data == "panel:words":
        await query.edit_message_text(
            "*🛑 Forbidden Words*\nA custom, editable blacklist. Any message containing a "
            "listed word (case-insensitive, whole-word match where possible) is deleted "
            "immediately.",
            parse_mode="Markdown",
            reply_markup=words_menu(chat_id),
        )
        return

    if data == "panel:english":
        await query.edit_message_text(
            "*🇬🇧 English Messages Protection*\nChoose how messages containing English "
            "(Latin) letters are handled:",
            parse_mode="Markdown",
            reply_markup=english_menu(chat_id),
        )
        return

    if data == "panel:admins":
        await query.edit_message_text(
            "*Admin management*\nTo add an admin, use /promote <user_id> in a private chat "
            "with the bot.\nTo remove one, use /demote <user_id>.\n"
            "To map a channel signature to an admin, use /setsignature <user_id> <signature>.\n\n"
            "Note: admins are NOT exempt from protection rules. Any violation by an admin "
            "automatically revokes their privileges, is logged, and privately notifies "
            "the Owner and all other admins.",
            parse_mode="Markdown",
            reply_markup=admins_menu(),
        )
        return

    if data == "panel:stats":
        stats = db.get_stats(chat_id)
        top = db.get_most_violating_user(chat_id)
        top_name = None
        if top:
            uid, count = top
            top_name = f"`{uid}` ({count} violations)"
        text = format_stats_text(chat_id, stats, top_name)
        await _replace_message(query, text, reply_markup=_wrap_rows([back_close_row()]))
        return

    if data == "panel:settings":
        await query.edit_message_text(
            "*General settings*",
            parse_mode="Markdown",
            reply_markup=settings_menu(),
        )
        return

    if data == "panel:logs":
        await query.edit_message_text("Choose a log type:", reply_markup=logs_menu())
        return

    # ---- Logs ----
    if data == "logs:violations":
        await _replace_message(
            query, _violations_text(chat_id),
            reply_markup=_wrap_rows([back_close_row()])
        )
        return

    if data == "logs:actions":
        await _replace_message(
            query, _actions_text(chat_id),
            reply_markup=_wrap_rows([back_close_row()])
        )
        return

    # ---- Admin list ----
    if data == "admins:list":
        admins = db.list_admins(chat_id)
        lines = ["*Admin list:*\n"]
        if not admins:
            lines.append("No admins yet.")
        for admin in admins:
            sig = f" (signature: {admin['signature']})" if admin.get("signature") else ""
            flag = " — RESTRICTED" if admin.get("restricted") else ""
            granted = [
                label for key, label in TELEGRAM_RIGHTS.items()
                if admin.get("telegram_rights", {}).get(key)
            ]
            rights_str = ", ".join(granted) if granted else "none"
            lines.append(f"- `{admin['user_id']}`{sig}{flag}\n  rights: {rights_str}")
        await _replace_message(
            query, "\n".join(lines),
            reply_markup=_wrap_rows([back_close_row()])
        )
        return

    # ---- Protection flags ----
    if data.startswith("flag:"):
        flag = data.split(":", 1)[1]
        settings = db.get_settings(chat_id)
        current = settings["flags"].get(flag, False)
        db.set_flag(chat_id, flag, not current)
        db.log_admin_action(chat_id, user.id, "toggle_flag", None, f"{flag}={not current}")
        await query.edit_message_reply_markup(reply_markup=protection_menu(chat_id))
        return

    # ---- Image mode ----
    if data.startswith("image:"):
        mode = data.split(":", 1)[1]
        if mode in IMAGE_MODES:
            db.set_image_mode(chat_id, mode)
            db.log_admin_action(chat_id, user.id, "set_image_mode", None, mode)
        await query.edit_message_reply_markup(reply_markup=image_menu(chat_id))
        return

    # ---- Punishment mode ----
    if data.startswith("punish:"):
        mode = data.split(":", 1)[1]
        if mode in PUNISHMENT_MODES:
            db.set_punishment_mode(chat_id, mode)
            db.log_admin_action(chat_id, user.id, "set_punishment_mode", None, mode)
        await query.edit_message_reply_markup(reply_markup=punishment_menu(chat_id))
        return

    # ---- Emergency ----
    if data == "emergency:toggle":
        settings = db.get_settings(chat_id)
        new_state = not settings.get("emergency_mode")
        db.log_admin_action(chat_id, user.id, "toggle_emergency", None, str(new_state))
        affected = await apply_emergency_mode(context, chat_id, user.id, new_state)

        if new_state:
            if affected:
                ids = ", ".join(f"`{a['user_id']}`" for a in affected)
                await query.message.reply_text(
                    f"Emergency mode is now ON. All admins have been restricted ({ids}) — "
                    "they can no longer post, edit, delete, or manage anything; only the "
                    "Owner has full access now. Their rights are re-enabled automatically "
                    "when emergency mode is turned off.",
                    parse_mode="Markdown",
                )
            else:
                await query.message.reply_text(
                    "Emergency mode is now ON. There were no admins to restrict."
                )
        else:
            if affected:
                ids = ", ".join(f"`{a['user_id']}`" for a in affected)
                await query.message.reply_text(
                    f"Emergency mode is now OFF. Rights restored for: {ids}.",
                    parse_mode="Markdown",
                )
            else:
                await query.message.reply_text("Emergency mode is now OFF.")

        await query.edit_message_reply_markup(reply_markup=emergency_menu(chat_id))
        return

    if data == "emergency:toggle_public":
        settings = db.get_settings(chat_id)
        new_state = not settings.get("public_alerts_enabled")
        db.set_public_alerts_enabled(chat_id, new_state)
        db.log_admin_action(chat_id, user.id, "toggle_public_alerts", None, str(new_state))
        await query.edit_message_reply_markup(reply_markup=emergency_menu(chat_id))
        return

    # ---- Forbidden words ----
    if data == "words:toggle":
        settings = db.get_settings(chat_id)
        new_state = not settings.get("forbidden_words_enabled")
        db.set_forbidden_words_enabled(chat_id, new_state)
        db.log_admin_action(chat_id, user.id, "toggle_forbidden_words", None, str(new_state))
        await query.edit_message_reply_markup(reply_markup=words_menu(chat_id))
        return

    if data == "words:list":
        words = db.list_forbidden_words(chat_id)
        text = "*Forbidden words:*\n\n" + (
            "\n".join(f"- {w}" for w in words) if words else "No words added yet."
        )
        await _replace_message(query, text[:4000], reply_markup=_wrap_rows([back_close_row()]))
        return

    if data == "words:add":
        _PENDING_INPUT[(chat_id, user.id)] = "words_add"
        await query.message.reply_text(
            "Send the word(s) to add — one per line, or comma-separated."
        )
        return

    if data == "words:remove":
        _PENDING_INPUT[(chat_id, user.id)] = "words_remove"
        await query.message.reply_text("Send the exact word to remove.")
        return

    if data == "words:search":
        _PENDING_INPUT[(chat_id, user.id)] = "words_search"
        await query.message.reply_text("Send a search term.")
        return

    if data == "words:import":
        _PENDING_INPUT[(chat_id, user.id)] = "words_import"
        await query.message.reply_text(
            "Paste the blacklist to import — one word per line, or comma-separated. "
            "Duplicates are skipped automatically."
        )
        return

    if data == "words:export":
        words = db.list_forbidden_words(chat_id)
        if not words:
            await query.message.reply_text("The blacklist is empty — nothing to export.")
            return
        await query.message.reply_text(
            "Blacklist export (one per line):\n\n" + "\n".join(words[:500])
        )
        return

    # ---- English mode ----
    if data.startswith("english:"):
        value = data.split(":", 1)[1]
        if value == "manage_users":
            _PENDING_INPUT[(chat_id, user.id)] = "english_selected_users"
            await query.message.reply_text(
                "Send the user IDs allowed to post English messages, comma-separated "
                "(replaces the current list). Send `clear` to empty it."
            )
            return
        if value in ENGLISH_MODES:
            db.set_english_mode(chat_id, value)
            db.log_admin_action(chat_id, user.id, "set_english_mode", None, value)
        await query.edit_message_reply_markup(reply_markup=english_menu(chat_id))
        return

    # ---- Settings (text-input prompts) ----
    if data.startswith("settings:"):
        field = data.split(":", 1)[1]
        prompts = {
            "alert_chat": (
                "Now send the ID of the alerts group/channel (usually a negative number)."
            ),
            "alert_template": (
                "Now send the new alert message text. You can use the placeholders:\n"
                "{violation} {name} {username} {user_id} {link} {time} {punishment} {original}"
            ),
            "mute_minutes": "Now send the new mute duration in minutes (number).",
            "ban_after_warnings": (
                "Now send the number of warnings required before an automatic ban (number)."
            ),
            "spam_thresholds": (
                "Now send the rate-limit thresholds as comma-separated count:seconds pairs, e.g.\n"
                "5:5,8:10,12:20\n"
                "(meaning: 5 messages in 5 s OR 8 in 10 s OR 12 in 20 s counts as spam)."
            ),
            "duplicate": (
                "Now send the duplicate-content settings as `repeat_count:window_seconds`, e.g.\n"
                "3:60\n"
                "(same text/media repeated 3 times within 60 seconds counts as spam)."
            ),
            "emergency_trigger_count": (
                "Now send the number of violations (channel-wide, any type) that should "
                "automatically turn emergency mode ON. Send 0 to disable auto-triggering."
            ),
        }
        prompt = prompts.get(field)
        if prompt is None:
            return
        _PENDING_INPUT[(chat_id, user.id)] = field
        await query.message.reply_text(prompt)
        return


async def handle_pending_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Consumes a message if the user has a pending settings-input request.
    Returns True if consumed so that other handlers should skip it."""
    user = update.effective_user
    if user is None:
        return False

    # Special case: adding a new managed chat (key is (-1, user_id), no chat context needed)
    add_key = (-1, user.id)
    if _PENDING_INPUT.get(add_key) == "add_chat":
        _PENDING_INPUT.pop(add_key, None)
        text = (update.effective_message.text or "").strip()
        raw = text.lstrip("-")
        if not raw.isdigit():
            await update.effective_message.reply_text(
                "❌ Invalid ID. Please send a numeric chat ID, e.g. `-1001234567890`.",
                parse_mode="Markdown",
            )
            return True
        new_chat_id = int(text)
        # Try to fetch the chat title via the Bot API for a nicer label
        title = str(new_chat_id)
        try:
            chat_obj = await context.bot.get_chat(new_chat_id)
            title = chat_obj.title or str(new_chat_id)
        except TelegramError:
            pass
        db.add_managed_chat(new_chat_id, title, user.id)
        db.ensure_group(new_chat_id, title, user.id)
        db.log_admin_action(new_chat_id, user.id, "add_managed_chat", None, title)
        log.info("Owner %s added managed chat %s (%s)", user.id, new_chat_id, title)
        await update.effective_message.reply_text(
            f"✅ *{title}* (`{new_chat_id}`) has been added to the managed chats list.\n\n"
            "The bot will now protect this chat. Make sure it is an admin there with "
            "permission to delete messages and ban members.",
            parse_mode="Markdown",
        )
        return True

    chat_id = _target_chat_id(user.id)
    if chat_id is None:
        return False
    key = (chat_id, user.id)
    field = _PENDING_INPUT.get(key)
    if field is None:
        return False

    text = update.effective_message.text or ""
    _PENDING_INPUT.pop(key, None)

    if field == "alert_chat":
        if text.strip().lstrip("-").isdigit():
            db.set_alert_chat(chat_id, int(text.strip()))
            await update.effective_message.reply_text("Alert channel updated.")
        else:
            await update.effective_message.reply_text("Invalid value, not saved.")

    elif field == "alert_template":
        db.set_alert_template(chat_id, text)
        await update.effective_message.reply_text("Alert message updated.")

    elif field == "mute_minutes":
        if text.strip().isdigit():
            db.set_mute_minutes(chat_id, int(text.strip()))
            await update.effective_message.reply_text("Mute duration updated.")
        else:
            await update.effective_message.reply_text("Invalid value, not saved.")

    elif field == "ban_after_warnings":
        if text.strip().isdigit():
            db.set_ban_after_warnings(chat_id, int(text.strip()))
            await update.effective_message.reply_text("Warning count updated.")
        else:
            await update.effective_message.reply_text("Invalid value, not saved.")

    elif field == "spam_thresholds":
        parsed = _parse_thresholds(text)
        if parsed:
            db.set_spam_thresholds(chat_id, parsed)
            await update.effective_message.reply_text("Rate-limit thresholds updated.")
        else:
            await update.effective_message.reply_text(
                "Invalid format, not saved. Use e.g. 5:5,8:10,12:20"
            )

    elif field == "duplicate":
        if ":" in text and all(p.strip().isdigit() for p in text.split(":", 1)):
            count_str, window_str = text.split(":", 1)
            db.set_duplicate_settings(chat_id, int(window_str.strip()), int(count_str.strip()))
            await update.effective_message.reply_text("Duplicate-content settings updated.")
        else:
            await update.effective_message.reply_text(
                "Invalid format, not saved. Use e.g. 3:60"
            )

    elif field == "emergency_trigger_count":
        if text.strip().isdigit():
            db.set_emergency_trigger_count(chat_id, int(text.strip()))
            note = (
                "disabled" if int(text.strip()) == 0
                else f"set to {text.strip()} violations"
            )
            await update.effective_message.reply_text(f"Auto-emergency trigger {note}.")
        else:
            await update.effective_message.reply_text("Invalid value, not saved.")

    elif field == "words_add":
        words = [w.strip() for chunk in text.split("\n") for w in chunk.split(",") if w.strip()]
        added = db.add_forbidden_words_bulk(chat_id, words, user.id)
        await update.effective_message.reply_text(
            f"Added {added} new word(s) ({len(words) - added} already existed)."
        )

    elif field == "words_remove":
        removed = db.remove_forbidden_word(chat_id, text.strip())
        await update.effective_message.reply_text(
            "Removed." if removed else "That word was not in the list."
        )

    elif field == "words_search":
        matches = db.search_forbidden_words(chat_id, text.strip())
        result = "\n".join(f"- {w}" for w in matches) if matches else "No matches."
        await update.effective_message.reply_text(
            f"Search results for '{text.strip()}':\n\n{result}"[:4000]
        )

    elif field == "words_import":
        words = [w.strip() for chunk in text.split("\n") for w in chunk.split(",") if w.strip()]
        added = db.add_forbidden_words_bulk(chat_id, words, user.id)
        await update.effective_message.reply_text(
            f"Import complete: {added} new word(s) added, "
            f"{len(words) - added} were already in the list."
        )

    elif field == "english_selected_users":
        if text.strip().lower() == "clear":
            db.set_english_selected_users(chat_id, [])
            await update.effective_message.reply_text("Selected-users list cleared.")
        else:
            ids = [
                int(chunk)
                for chunk in text.split(",")
                if chunk.strip().lstrip("-").isdigit()
            ]
            db.set_english_selected_users(chat_id, ids)
            await update.effective_message.reply_text(
                f"Selected users updated: {ids or 'none'}"
            )

    db.log_admin_action(chat_id, user.id, f"update_setting:{field}", None, text[:100])
    return True


# =============================================================================
# 18. APPLICATION BOOTSTRAP & ENTRY-POINT
# =============================================================================

async def _on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    log.exception(
        "Unhandled exception while processing update: %s", update, exc_info=context.error
    )


async def _owner_private_gate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ignore private traffic from everyone except configured owners.

    Channel posts are intentionally not blocked here: the protection engine
    must inspect those posts regardless of who published them. Private
    commands, text prompts, and callback buttons are control traffic and are
    therefore accepted only from an owner before any other handler runs.
    """
    user = update.effective_user
    chat = update.effective_chat
    if user is None or chat is None or chat.type != "private":
        return
    if db.is_owner(user.id):
        return
    raise ApplicationHandlerStop


async def _allowed_chat_gate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Restricts the bot to the managed chats list only.
    Any chat (group, channel, supergroup) not in the list is ignored.
    The bot stays in unmanaged chats so it can be added to them later."""
    chat = update.effective_chat
    if chat is None or chat.type == "private":
        return

    if db.is_managed_chat(chat.id):
        # Keep the stored title current
        if chat.title:
            db.update_managed_chat_title(chat.id, chat.title)
        return

    # Do not leave unmanaged chats. The owner can add one from the panel
    # after the bot has been added there.
    raise ApplicationHandlerStop


async def _text_gate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Runs before the protection engine: intercepts messages that are replies
    to a control-panel text prompt (e.g. setting the alert template)."""
    if update.effective_message and update.effective_message.text:
        consumed = await handle_pending_text_input(update, context)
        if consumed:
            raise ApplicationHandlerStop


def build_application() -> Application:
    application = Application.builder().token(config.bot_token).build()

    # --- Ignore private messages/callbacks from non-owners before dispatch ---
    # This prevents unsolicited private traffic from reaching commands,
    # pending-input handlers, or the control panel.
    application.add_handler(MessageHandler(filters.ALL, _owner_private_gate), group=-3)
    application.add_handler(CallbackQueryHandler(_owner_private_gate), group=-3)

    # --- Restrict the bot to a single configured chat (must run first, group=-2) ---
    application.add_handler(MessageHandler(filters.ALL, _allowed_chat_gate), group=-2)
    application.add_handler(CallbackQueryHandler(_allowed_chat_gate), group=-2)
    application.add_handler(
        ChatMemberHandler(_allowed_chat_gate, ChatMemberHandler.MY_CHAT_MEMBER), group=-2
    )

    # --- General commands ---
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))

    # --- Panel / settings ---
    application.add_handler(CommandHandler("panel", panel_command))
    application.add_handler(CommandHandler("settings", settings_command))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CallbackQueryHandler(callback_router))

    # --- Stats / emergency ---
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("emergency", emergency_command))

    # --- Admin management ---
    application.add_handler(CommandHandler("promote", promote_command))
    application.add_handler(CommandHandler("demote", demote_command))
    application.add_handler(CommandHandler("restrict", restrict_command))
    application.add_handler(CommandHandler("unrestrict", unrestrict_command))
    application.add_handler(CommandHandler("setright", setright_command))
    application.add_handler(CommandHandler("rights", rights_command))
    application.add_handler(CommandHandler("admins", admins_command))
    application.add_handler(CommandHandler("setsignature", setsignature_command))

    # --- Manual moderation ---
    application.add_handler(CommandHandler("ban", ban_command))
    application.add_handler(CommandHandler("unban", unban_command))
    application.add_handler(CommandHandler("mute", mute_command))
    application.add_handler(CommandHandler("unmute", unmute_command))
    application.add_handler(CommandHandler("warn", warn_command))
    application.add_handler(CommandHandler("unwarn", unwarn_command))

    # --- Pending settings text-input gate (must run before the protection engine) ---
    application.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND & filters.ChatType.PRIVATE, _text_gate
        ),
        group=0,
    )
    application.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND & filters.UpdateType.CHANNEL_POST, _text_gate
        ),
        group=0,
    )

    # --- Core protection engine (channel posts only) ---
    application.add_handler(
        MessageHandler(
            filters.UpdateType.CHANNEL_POST & ~filters.COMMAND, handle_new_post
        ),
        group=1,
    )
    application.add_handler(
        MessageHandler(filters.UpdateType.EDITED_CHANNEL_POST, handle_edited_post),
        group=1,
    )

    # --- Track when the bot is added to the channel ---
    application.add_handler(
        ChatMemberHandler(track_new_group, ChatMemberHandler.MY_CHAT_MEMBER)
    )

    application.add_error_handler(_on_error)
    return application


def main():
    log.info("Starting Telegram Protection Bot...")
    application = build_application()
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
