import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import ipaddress
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import uvicorn
import httpx
import psutil
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import aiosqlite
import logging
import logging.config

try:
    from pythonjsonlogger import jsonlogger
    HAS_JSON_LOGGER = True
except Exception:
    HAS_JSON_LOGGER = False

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

if HAS_JSON_LOGGER:
    LOGGING_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            }
        },
        "handlers": {"json_console": {"class": "logging.StreamHandler", "formatter": "json"}},
        "root": {"level": "INFO", "handlers": ["json_console"]},
    }
else:
    LOGGING_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "plain": {
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            }
        },
        "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
        "root": {"level": "INFO", "handlers": ["console"]},
    }

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("BestPanel")
print("--- APPLICATION IS STARTING ---")
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "/data/panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

if HAS_POSTGRES:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError)
else:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError,)

db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True
KEEP_ALIVE_INTERVAL = 300
TIMEZONE_OFFSET = 0.0
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"

traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {
    "hourly": defaultdict(int),
    "daily": defaultdict(int),
}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

_scan_lock = asyncio.Lock()

if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                    limit_bytes BIGINT DEFAULT 0, used_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0, created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE, expires_at TEXT,
                    custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                    custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                    color TEXT DEFAULT '#39ff14',
                    flag TEXT DEFAULT '',
                    fragment TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS custom_addresses (id SERIAL PRIMARY KEY, address TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS login_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    success BOOLEAN DEFAULT TRUE,
                    user_agent TEXT DEFAULT '',
                    path TEXT DEFAULT ''
                );
            """)
            try:
                await conn.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS flag TEXT DEFAULT ''")
            except Exception:
                pass
            try:
                await conn.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS fragment TEXT DEFAULT ''")
            except Exception:
                pass

    async def db_execute(sqlite_q: str, pg_q: str, params: tuple = ()):
        async with pg_pool.acquire() as conn:
            await conn.execute(pg_q, *params)

    async def db_fetchall(sqlite_q: str, pg_q: str, params: tuple = ()) -> list:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(pg_q, *params)
            return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str, params: tuple = ()) -> Optional[dict]:
        async with pg_pool.acquire() as conn:
            row = await conn.fetchrow(pg_q, *params)
            return dict(row) if row else None

    async def get_db():
        return None
else:
    DB_BACKEND = "sqlite"

    async def init_db():
        global db_conn
        db_path = CONFIG["db_path"]
        try:
            test_file = os.path.join(os.path.dirname(db_path), ".write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            logger.warning(f"Cannot write to {db_path}, falling back to /tmp/panel.db")
            CONFIG["db_path"] = "/tmp/panel.db"
            db_path = "/tmp/panel.db"
        db_conn = await aiosqlite.connect(db_path)
        db_conn.row_factory = aiosqlite.Row
        await db_conn.execute("PRAGMA journal_mode=WAL")
        await db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS links (
                uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                limit_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1, expires_at TEXT,
                custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                color TEXT DEFAULT '#39ff14',
                flag TEXT DEFAULT '',
                fragment TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS custom_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                success INTEGER DEFAULT 1,
                user_agent TEXT DEFAULT '',
                path TEXT DEFAULT ''
            );
        """)
        try:
            await db_conn.execute("ALTER TABLE links ADD COLUMN flag TEXT DEFAULT ''")
        except Exception:
            pass
        try:
            await db_conn.execute("ALTER TABLE links ADD COLUMN fragment TEXT DEFAULT ''")
        except Exception:
            pass
        await db_conn.commit()

    async def db_execute(sqlite_q: str, pg_q: str = "", params: tuple = ()):
        async with db_lock:
            await db_conn.execute(sqlite_q, params)
            await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> list:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> Optional[dict]:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_db():
        return db_conn

async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        try:
            async with traffic_buffer_lock:
                if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                    continue
                for hour, bytes_val in traffic_buffer["hourly"].items():
                    await db_execute(
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                        (hour, bytes_val, bytes_val)
                    )
                for day, bytes_val in traffic_buffer["daily"].items():
                    await db_execute(
                        "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                        (day, bytes_val, bytes_val)
                    )
                traffic_buffer["hourly"].clear()
                traffic_buffer["daily"].clear()
        except Exception as e:
            logger.error(f"flush_traffic_buffer error: {e}", exc_info=True)

async def add_traffic_to_buffer(hour: str, day: str, size: int):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size

async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        try:
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    await db_execute(
                        "UPDATE links SET used_bytes = ? WHERE uid = ?",
                        "UPDATE links SET used_bytes = $1 WHERE uid = $2",
                        (link["used_bytes"], uid)
                    )
        except Exception as e:
            logger.error(f"sync_usage_to_db error: {e}", exc_info=True)

async def load_initial_data():
    rows = await db_fetchall("SELECT * FROM links", "SELECT * FROM links")
    async with LINKS_LOCK:
        for r in rows:
            LINKS[r["uid"]] = dict(r)
    addr_rows = await db_fetchall("SELECT address FROM custom_addresses", "SELECT address FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
    if not CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append("www.speedtest.net")
    if not LINKS:
        default_uuid = str(uuid_lib.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        default_link = {
            "uid": default_uuid, "label": "This Server is Free", "limit_bytes": 0, "used_bytes": 0,
            "max_connections": 0, "created_at": now, "active": 1, "expires_at": None,
            "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome",
            "color": "#39ff14", "flag": "", "fragment": ""
        }
        async with LINKS_LOCK:
            LINKS[default_uuid] = default_link
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES (?,?,?,?,?,1,?,'','')",
            "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, flag, fragment) VALUES ($1,$2,$3,$4,$5,TRUE,$6,'','')",
            (default_uuid, "This Server is Free", 0, 0, now, None),
        )
    total_usage = sum(link.get("used_bytes", 0) for link in LINKS.values())
    stats["total_bytes"] = total_usage

async def _keepalive_simple_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    while True:
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "simple":
            continue
        domain = get_domain()
        if domain == "localhost":
            continue
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://{domain}/health")
                if resp.status_code == 200:
                    logger.info(f"Simple keep-alive successful: {domain}/health")
        except Exception:
            pass

async def _keepalive_advanced_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    await asyncio.sleep(30)
    while True:
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "advanced":
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            continue
        domain = os.environ.get("DOMAIN", "").strip()
        port = os.environ.get("PORT", "8000")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        target_urls = []
        if domain:
            if not domain.startswith(("http://", "https://")):
                target_urls.append(f"https://{domain}/login")
                target_urls.append(f"http://{domain}/login")
            else:
                target_urls.append(f"{domain}/login")
        target_urls.append(f"http://127.0.0.1:{port}/login")
        async with httpx.AsyncClient(verify=False, timeout=15.0, headers=headers) as client:
            success = False
            for url in target_urls:
                try:
                    final_url = url + ("&" if "?" in url else "?") + f"_nocache={secrets.token_hex(4)}"
                    resp = await client.get(final_url, follow_redirects=True)
                    if resp.status_code == 200:
                        logger.info(f"Advanced keep-alive successful: {url}")
                        success = True
                        break
                except Exception as e:
                    logger.debug(f"Advanced keep-alive attempt failed for {url}: {e}")
            if not success:
                logger.warning("Advanced keep-alive: all attempts failed.")
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)

async def cleanup_link_cache():
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [k for k, v in link_cache.items() if v["expires"] <= now]
        for k in expired:
            del link_cache[k]

@asynccontextmanager
async def lifespan(app: FastAPI):
    global TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    await load_initial_data()

    sk = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'",
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'"
    )
    if sk:
        CONFIG["secret_key"] = sk["value"]
    else:
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', ?)",
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', $1)",
            (CONFIG["secret_key"],)
        )

    hash_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
    )
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute(
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)",
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
            (ADMIN_PASSWORD_HASH,),
        )

    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'log_enabled'",
        "SELECT value FROM settings WHERE key = 'log_enabled'"
    )
    global ENABLE_LOGGING
    ENABLE_LOGGING = (log_row and log_row["value"] == "1") if log_row else True

    tz_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='timezone_offset'",
        "SELECT value FROM settings WHERE key='timezone_offset'"
    )
    if tz_row and tz_row["value"]:
        try:
            TIMEZONE_OFFSET = float(tz_row["value"])
        except:
            TIMEZONE_OFFSET = 0.0

    ke_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_enabled'",
        "SELECT value FROM settings WHERE key='keep_alive_enabled'"
    )
    if ke_row and ke_row["value"] is not None:
        KEEP_ALIVE_ENABLED = (ke_row["value"] == "1")

    km_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_mode'",
        "SELECT value FROM settings WHERE key='keep_alive_mode'"
    )
    if km_row and km_row["value"]:
        KEEP_ALIVE_MODE = km_row["value"]

    interval_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_interval'",
        "SELECT value FROM settings WHERE key='keep_alive_interval'"
    )
    if interval_row and interval_row["value"]:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(interval_row["value"]))
        except:
            pass

    asyncio.create_task(_keepalive_simple_loop())
    asyncio.create_task(_keepalive_advanced_loop())
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(telegram_reporter())
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    asyncio.create_task(auto_disable_expired_links())
    asyncio.create_task(cleanup_link_cache())
    yield
    if DB_BACKEND == "sqlite" and db_conn:
        await db_conn.close()

app = FastAPI(title="Best Panel", lifespan=lifespan, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response

connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
    "upload_bytes": 0,
    "download_bytes": 0,
}
error_logs: deque = deque(maxlen=2000)

CACHE_TTL = 60
link_cache: dict = {}

SESSION_COOKIE = "SulgX_session"
UNLIMITED_QUOTA_BYTES = 53687091200000

ADMIN_PASSWORD_HASH: str = ""
ENABLE_LOGGING: bool = True
KEEP_ALIVE_ENABLED: bool = True
KEEP_ALIVE_MODE: str = "simple"

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=CONFIG["jwt_expire_minutes"]))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG["secret_key"], algorithm=CONFIG["jwt_algorithm"])

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, CONFIG["secret_key"], algorithms=[CONFIG["jwt_algorithm"]])
    except JWTError:
        return None

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def cleanup_idle_connections():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with connections_lock:
            idle = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle:
            ws = connection_sockets.get(cid)
            if ws:
                try: await ws.close(code=1000, reason="idle timeout")
                except Exception: pass
            async with connections_lock: connections.pop(cid, None)
            connection_sockets.pop(cid, None)

async def auto_disable_expired_links():
    while True:
        await asyncio.sleep(60)
        try:
            row = await db_fetchone("SELECT value FROM settings WHERE key='auto_disable_enabled'", "SELECT value FROM settings WHERE key='auto_disable_enabled'")
            if row and row["value"] != "1":
                continue
            now = datetime.now(timezone.utc)
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    if link.get("active") and link.get("expires_at"):
                        exp = parse_expires_at(link["expires_at"])
                        if exp and exp < now:
                            link["active"] = 0
                            await db_execute("UPDATE links SET active = 0 WHERE uid = ?", "UPDATE links SET active = FALSE WHERE uid = $1", (uid,))
                            log_event("Auto", f"Expired inbound {link['label']} auto-disabled")
        except Exception as e:
            logger.error(f"auto_disable_expired_links error: {e}", exc_info=True)

async def telegram_reporter():
    while True:
        interval_hours = 1
        row = await db_fetchone("SELECT value FROM settings WHERE key = 'telegram_interval'", "SELECT value FROM settings WHERE key = 'telegram_interval'")
        if row and row["value"]:
            try: interval_hours = float(row["value"])
            except: interval_hours = 1
        await asyncio.sleep(3600 * interval_hours)
        en_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_report_enabled'", "SELECT value FROM settings WHERE key='telegram_report_enabled'")
        if en_row and en_row["value"] != "1":
            continue
        try:
            token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
            chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
            if token_row and chat_row and token_row["value"] and chat_row["value"]:
                msg = (
                    f"📊 Best Panel Stats\n"
                    f"🕒 Uptime: {uptime()}\n"
                    f"🔗 Conns: {len(connections)}\n"
                    f"📦 Traffic: {round(stats['total_bytes']/(1024*1024),2)} MB\n"
                    f"📡 Requests: {stats['total_requests']}\n"
                    f"❌ Errors: {stats['total_errors']}"
                )
                url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json={"chat_id": chat_row["value"], "text": msg})
        except Exception:
            pass

def get_domain() -> str:
    domain = (
        os.environ.get("DOMAIN") or
        os.environ.get("RENDER_EXTERNAL_URL") or
        os.environ.get("RAILWAY_PUBLIC_DOMAIN") or
        "localhost"
    )
    return domain.replace("https://", "").replace("http://", "")

def validate_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip('[]'))
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(addr.strip('[]'), strict=False)
        return True
    except ValueError:
        pass
    return re.match(r'^[a-zA-Z0-9\-_.%]+$', addr) is not None

def format_host_port(host: str, port: int = 443) -> str:
    host = host.strip('[]')
    try:
        ipaddress.IPv6Address(host)
        return f"[{host}]:{port}"
    except ipaddress.AddressValueError:
        return f"{host}:{port}"

def code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    code = code.upper()
    try:
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except:
        return ""

def generate_vless_link(uid: str, remark: str = "SulgX", address: str = None, extra: dict = None) -> str:
    cache_key = f"{uid}:{remark}:{address}:{json.dumps(extra) if extra else ''}"
    if cache_key in link_cache and link_cache[cache_key]["expires"] > time.time():
        return link_cache[cache_key]["link"]
    domain = get_domain()
    addr = address if address else domain
    path = (extra.get("custom_path") or f"/ws/{uid}") if extra else f"/ws/{uid}"
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fp = (extra.get("custom_fp") or "chrome") if extra else "chrome"
    fragment = extra.get("fragment", "") if extra else ""
    params = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": host, "path": path, "sni": sni, "fp": fp, "alpn": "http/1.1"
    }
    if fragment:
        params["fragment"] = fragment
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    link = f"vless://{uid}@{format_host_port(addr, 443)}?{query}#{quote(remark)}"
    link_cache[cache_key] = {"link": link, "expires": time.time() + CACHE_TTL}
    return link

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB": return int(value * 1024**3)
    if u == "MB": return int(value * 1024**2)
    if u == "KB": return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw: return None
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception: return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None: return None
    return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_link(uid: str):
    async with connections_lock:
        to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason="link deleted/blocked")
            except Exception: pass
        async with connections_lock: connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock: link_ip_map.pop(uid, None)

def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "type": etype,
        "error": message or "(no detail)",
        "ip": ip,
        "ua": ua,
    })

# ═══ ROUTES ═══

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"service": "Best Panel", "version": "1.1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    async with connections_lock: cnt = len(connections)
    return {"status": "ok", "connections": cnt, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/api/public-settings")
async def public_settings():
    rows = await db_fetchall("SELECT key, value FROM settings WHERE key IN ('footer_text')",
                             "SELECT key, value FROM settings WHERE key IN ('footer_text')")
    result = {}
    for r in rows:
        result[r["key"]] = r["value"]
    return result

@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    success = verify_password(password, ADMIN_PASSWORD_HASH)
    asyncio.create_task(log_login(ip, success, user_agent, "/api/login"))
    if not success:
        log_event("Auth", f"Failed login attempt from {ip}", ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid password")
    log_event("Auth", f"Successful panel login from {ip}", ip, user_agent)
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=CONFIG["jwt_expire_minutes"]*60,
                    httponly=True, samesite="lax", secure=True if get_domain()!="localhost" else False, path="/")
    return resp

async def log_login(ip: str, success: bool, ua: str, path: str):
    if not ENABLE_LOGGING:
        return
    try:
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES (?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path) VALUES ($1,$2,$3,$4,$5)",
            (datetime.now(timezone.utc).isoformat(), ip, 1 if success else 0, ua, path)
        )
        if success:
            await notify_telegram_login(ip, ua)
    except Exception as e:
        logger.error(f"log_login error: {e}")

async def notify_telegram_login(ip: str, ua: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    if lang == 'fa':
        default_login = f"🔐 ورود SulgX\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {now_str}"
    else:
        default_login = f"🔐 Best Panel login\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {now_str}"
    msg = templates.get('login', default_login)
    msg = msg.replace("{ip}", ip).replace("{ua}", ua).replace("{time}", now_str)
    panel_url = f"https://{get_domain()}/panel"
    msg += f'\n\n<a href="{panel_url}">Open Best Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except Exception:
        pass

@app.post("/api/logout")
async def api_logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(_: str = Depends(require_auth)):
    return {"authenticated": True}

@app.post("/api/change-password")
@limiter.limit("3/minute")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global ADMIN_PASSWORD_HASH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[A-Z]', new) or not re.search(r'[a-z]', new) or not re.search(r'[0-9]', new):
        raise HTTPException(status_code=400, detail="Password must contain uppercase, lowercase, and digit")
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    ADMIN_PASSWORD_HASH = new_hash
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (new_hash,),
    )
    log_event("Security", "Admin password changed")
    return {"ok": True}

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = ['tg_bot_token', 'max_scan_ips', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
            'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
            'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
            'log_max_entries', 'scanner_timeout', 'theme_color',
            'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
            'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
            'monthly_limit_gb']
    result = {}
    for k in keys:
        row = await db_fetchone("SELECT value FROM settings WHERE key = ?", "SELECT value FROM settings WHERE key = $1", (k,))
        result[k] = row["value"] if row else ""
    return result

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
    global ENABLE_LOGGING, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE
    body = await request.json()
    for k in ('tg_bot_token', 'tg_chat_id', 'max_scan_ips', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
              'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
              'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
              'log_max_entries', 'scanner_timeout', 'theme_color',
              'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
              'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
              'monthly_limit_gb'):
        if k in body:
            val = str(body[k]).strip()
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, val),
            )
    if 'log_enabled' in body:
        ENABLE_LOGGING = body['log_enabled'] == '1'
    if 'keep_alive_enabled' in body:
        KEEP_ALIVE_ENABLED = body['keep_alive_enabled'] == '1'
    if 'keep_alive_mode' in body:
        KEEP_ALIVE_MODE = body['keep_alive_mode']
    if 'keep_alive_interval' in body:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(body['keep_alive_interval']))
        except:
            pass
    if 'timezone_offset' in body:
        try:
            TIMEZONE_OFFSET = float(body['timezone_offset'])
        except:
            TIMEZONE_OFFSET = 0.0
    return {"ok": True}

@app.post("/api/settings/reset")
@limiter.limit("3/minute")
async def reset_settings(request: Request, _=Depends(require_auth)):
    PROTECTED_KEYS = {'jwt_secret_key', 'admin_password_hash'}
    all_keys = await db_fetchall("SELECT key FROM settings", "SELECT key FROM settings")
    for row in all_keys:
        k = row["key"]
        if k not in PROTECTED_KEYS:
            await db_execute("DELETE FROM settings WHERE key = ?", "DELETE FROM settings WHERE key = $1", (k,))
    global ENABLE_LOGGING, KEEP_ALIVE_INTERVAL, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    ENABLE_LOGGING = True
    KEEP_ALIVE_INTERVAL = 300
    TIMEZONE_OFFSET = 0.0
    KEEP_ALIVE_ENABLED = True
    KEEP_ALIVE_MODE = "simple"
    log_event("Settings", "All settings reset to defaults")
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    global TIMEZONE_OFFSET
    async with connections_lock: conn_count = len(connections)
    cpu = 0.0
    try:
        cpu = await asyncio.to_thread(psutil.cpu_percent, 0.1)
        if cpu == 0.0:
            try:
                with open('/proc/loadavg', 'r') as f:
                    cpu = float(f.readline().split()[0]) * 10
            except:
                cpu = None
    except:
        try:
            with open('/proc/loadavg', 'r') as f:
                cpu = float(f.readline().split()[0]) * 10
        except:
            cpu = None
    mem_percent = 0
    try: mem_percent = psutil.virtual_memory().percent
    except: pass
    disk_percent = 0; disk_free = 0.0
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_free = round(disk.free / (1024**3), 1)
    except: pass
    now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
    today_str = now.strftime("%Y-%m-%d")
    rows = await db_fetchall(
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE ? ORDER BY hour ASC",
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE $1 ORDER BY hour ASC",
        (today_str + '%',)
    )
    hourly_dict = {f"{h:02d}:00": 0 for h in range(24)}
    for r in rows:
        hour_part = r["hour"][-5:] if len(r["hour"]) >= 5 else r["hour"]
        if hour_part in hourly_dict:
            hourly_dict[hour_part] = r["bytes"]
    async with traffic_buffer_lock:
        for h_key, b_val in traffic_buffer["hourly"].items():
            hour_part = h_key[-5:] if len(h_key) >= 5 else h_key
            if hour_part in hourly_dict:
                hourly_dict[hour_part] += b_val
    sorted_hours = [f"{h:02d}:00" for h in range(24)]
    hourly_data = {h: hourly_dict[h] for h in sorted_hours}
    month_start = now.strftime("%Y-%m") + "-01"
    monthly_bytes = 0
    month_rows = await db_fetchall(
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= ?",
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= $1",
        (month_start,)
    )
    if month_rows and month_rows[0]["total"]:
        monthly_bytes = month_rows[0]["total"]
    monthly_limit = 0
    limit_row = await db_fetchone("SELECT value FROM settings WHERE key='monthly_limit_gb'", "SELECT value FROM settings WHERE key='monthly_limit_gb'")
    if limit_row and limit_row["value"]:
        try: monthly_limit = float(limit_row["value"]) * 1024**3
        except: pass
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-20:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "hourly_traffic": hourly_data,
        "hourly_labels": sorted_hours,
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
        "monthly_usage_bytes": monthly_bytes,
        "monthly_limit_bytes": int(monthly_limit),
    }

@app.get("/stats/detailed")
async def get_detailed_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    active = sum(1 for l in links if l["active"])
    inactive = sum(1 for l in links if not l["active"])
    expired = 0
    now = datetime.now(timezone.utc)
    for l in links:
        if l.get("expires_at"):
            exp = parse_expires_at(l["expires_at"])
            if exp and exp < now:
                expired += 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_row = await db_fetchone("SELECT bytes FROM daily_traffic WHERE day = ?", "SELECT bytes FROM daily_traffic WHERE day = $1", (today,))
    today_bytes = today_row["bytes"] if today_row else 0
    daily_rows = await db_fetchall("SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7",
                                   "SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7")
    daily_traffic = {row["day"]: row["bytes"] for row in daily_rows}
    return {
        "total_links": len(links),
        "active_links": active,
        "inactive_links": inactive,
        "expired_links": expired,
        "today_traffic_bytes": today_bytes,
        "daily_traffic": daily_traffic,
    }

@app.get("/api/login-logs")
async def get_login_logs(_=Depends(require_auth)):
    rows = await db_fetchall(
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20",
        "SELECT timestamp, ip, success, user_agent, path FROM login_logs ORDER BY timestamp DESC LIMIT 20"
    )
    return {"logs": [dict(r) for r in rows]}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.delete("/api/logs/clear")
async def clear_logs(_=Depends(require_auth)):
    error_logs.clear()
    await db_execute("DELETE FROM login_logs", "DELETE FROM login_logs")
    return {"ok": True}

@app.get("/api/logs/size")
async def logs_size(_=Depends(require_auth)):
    total_chars = sum(len(json.dumps(log)) for log in error_logs)
    return {"count": len(error_logs), "size_kb": round(total_chars / 1024, 2)}

@app.get("/api/backup/full")
async def full_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    rows = await db_fetchall("SELECT key, value FROM settings", "SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in rows}
    backup = {"links": links, "addresses": addrs, "settings": settings}
    return backup

MAX_RESTORE_SIZE = 5 * 1024 * 1024

@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_RESTORE_SIZE:
        raise HTTPException(status_code=413, detail="Backup file too large")
    body = await request.json()
    if "settings" in body:
        for k, v in body["settings"].items():
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, str(v))
            )
    if "addresses" in body:
        await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES[:] = []
            for a in body["addresses"]:
                addr = str(a).strip()
                if addr and validate_address(addr):
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
    if "links" in body:
        await db_execute("DELETE FROM links", "DELETE FROM links")
        async with LINKS_LOCK:
            LINKS.clear()
        for link in body["links"]:
            uid = link.get("uid") or str(uuid_lib.uuid4())
            label = link.get("label", "Restored")
            limit_bytes = int(link.get("limit_bytes", 0))
            used_bytes = int(link.get("used_bytes", 0))
            max_conn = int(link.get("max_connections", 0))
            created_at = link.get("created_at") or datetime.now(timezone.utc).isoformat()
            active = 1 if link.get("active", True) else 0
            expires_at = link.get("expires_at")
            custom_path = link.get("custom_path", "")
            custom_sni = link.get("custom_sni", "")
            custom_host = link.get("custom_host", "")
            custom_fp = link.get("custom_fp", "chrome")
            color = link.get("color", "#39ff14")
            flag = link.get("flag", "")
            fragment = link.get("fragment", "")
            await db_execute(
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
                (uid, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
            )
            async with LINKS_LOCK:
                LINKS[uid] = {
                    "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                    "max_connections": max_conn, "created_at": created_at, "active": active,
                    "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                    "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
                }
    return {"ok": True}

# ═══ INBOUNDS ═══

@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "This Server is Free").strip()[:60]
    uuid_input = (body.get("uuid") or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="Remark is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Remark must contain only English letters, numbers, and characters: - _ . space")
    if uuid_input:
        try:
            uuid_lib.UUID(uuid_input)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid UUID format")
        uid = uuid_input
    else:
        uid = str(uuid_lib.uuid4())
    async with LINKS_LOCK:
        if uid in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this UUID already exists")
    default_limit = 0
    def_limit_row = await db_fetchone("SELECT value FROM settings WHERE key='default_limit_bytes'", "SELECT value FROM settings WHERE key='default_limit_bytes'")
    if def_limit_row and def_limit_row["value"]:
        default_limit = int(def_limit_row["value"])
    default_expiry_days = 0
    def_exp_row = await db_fetchone("SELECT value FROM settings WHERE key='default_expiry_days'", "SELECT value FROM settings WHERE key='default_expiry_days'")
    if def_exp_row and def_exp_row["value"]:
        default_expiry_days = int(def_exp_row["value"])
    default_max_conn = 0
    def_conn_row = await db_fetchone("SELECT value FROM settings WHERE key='default_max_connections'", "SELECT value FROM settings WHERE key='default_max_connections'")
    if def_conn_row and def_conn_row["value"]:
        default_max_conn = int(def_conn_row["value"])

    limit_val = float(body.get("limit_value") or default_limit)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, limit_unit)
    max_conn = int(body.get("max_connections") or default_max_conn)
    if max_conn < 0: max_conn = 0
    days_valid = body.get("days_valid") if body.get("days_valid") is not None else default_expiry_days
    expires_at = None
    try:
        days_valid = int(days_valid)
        if days_valid > 0: expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
    except (ValueError, TypeError): pass
    now = datetime.now(timezone.utc).isoformat()
    custom_path = body.get("custom_path", "")
    custom_sni = body.get("custom_sni", "")
    custom_host = body.get("custom_host", "")
    custom_fp = body.get("custom_fp", "chrome")
    color = body.get("color", "#39ff14")
    flag = body.get("flag", "")
    fragment = body.get("fragment", "")
    if flag:
        flag = flag.strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag):
            flag = ""
        else:
            flag = flag.upper()
    if fragment:
        fragment = fragment.strip()[:50]
    link_data = {
        "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "created_at": now, "active": 1,
        "expires_at": expires_at,
        "custom_path": custom_path, "custom_sni": custom_sni,
        "custom_host": custom_host, "custom_fp": custom_fp, "color": color,
        "flag": flag, "fragment": fragment,
    }
    async with LINKS_LOCK:
        LINKS[uid] = link_data
    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?,?)",
        "INSERT INTO links (uid, label, limit_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7,$8,$9,$10,$11,$12,$13)",
        (uid, label, limit_bytes, max_conn, now, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
    )
    extra = {"custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host, "custom_fp": custom_fp, "fragment": fragment}
    log_event("Inbound", f"Created inbound {label} ({uid})")
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at, "color": color, "flag": flag, "fragment": fragment,
        "vless_link": generate_vless_link(uid, remark=f"SulgX-{label}", extra=extra),
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    items.sort(key=lambda x: x["created_at"], reverse=True)
    result = []
    for row in items:
        uid = row["uid"]
        extra = {
            "custom_path": row.get("custom_path", ""),
            "custom_sni": row.get("custom_sni", ""),
            "custom_host": row.get("custom_host", ""),
            "custom_fp": row.get("custom_fp", "chrome"),
            "fragment": row.get("fragment", ""),
        }
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row.get("expires_at"),
            "custom_path": extra["custom_path"],
            "custom_sni": extra["custom_sni"],
            "custom_host": extra["custom_host"],
            "custom_fp": extra["custom_fp"],
            "color": row.get("color", "#39ff14"),
            "flag": row.get("flag", ""),
            "fragment": row.get("fragment", ""),
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"SulgX-{row['label']}", extra=extra),
        })
    return {"links": result}

@app.get("/api/export-links")
async def export_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    return JSONResponse(content=links)

@app.post("/api/import-links")
async def import_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = 0
    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Expected a list of links")
    for item in body:
        if not isinstance(item, dict):
            continue
        uid_input = item.get("uid") or str(uuid_lib.uuid4())
        try:
            uuid_lib.UUID(uid_input)
        except ValueError:
            continue
        label = item.get("label", "Imported")[:60]
        if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
            continue
        limit_bytes = int(item.get("limit_bytes", 0))
        used_bytes = int(item.get("used_bytes", 0))
        max_conn = int(item.get("max_connections", 0))
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if item.get("active", True) else 0
        expires_at = item.get("expires_at")
        custom_path = item.get("custom_path", "")
        custom_sni = item.get("custom_sni", "")
        custom_host = item.get("custom_host", "")
        custom_fp = item.get("custom_fp", "chrome")
        color = item.get("color", "#39ff14")
        flag = item.get("flag", "")
        fragment = item.get("fragment", "")
        if flag:
            flag = flag.strip()[:2]
            if not re.match(r'^[a-zA-Z]{2}$', flag):
                flag = ""
            else:
                flag = flag.upper()
        async with LINKS_LOCK:
            if uid_input in LINKS:
                continue
            LINKS[uid_input] = {
                "uid": uid_input, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                "max_connections": max_conn, "created_at": created_at, "active": active,
                "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
            }
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            (uid_input, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment),
        )
        imported += 1
    return {"ok": True, "imported": imported}

@app.patch("/api/links/batch")
async def batch_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uids = body.get("uids", [])
    action = body.get("action", "")
    async with LINKS_LOCK:
        for uid in uids:
            link = LINKS.get(uid)
            if not link: continue
            if action == "activate":
                link["active"] = 1
                await db_execute("UPDATE links SET active=1 WHERE uid=?", "UPDATE links SET active=TRUE WHERE uid=$1", (uid,))
            elif action == "deactivate":
                link["active"] = 0
                await db_execute("UPDATE links SET active=0 WHERE uid=?", "UPDATE links SET active=FALSE WHERE uid=$1", (uid,))
                await close_connections_for_link(uid)
            elif action == "reset_usage":
                link["used_bytes"] = 0
                await db_execute("UPDATE links SET used_bytes=0 WHERE uid=?", "UPDATE links SET used_bytes=0 WHERE uid=$1", (uid,))
            elif action == "delete":
                if link.get("label") == "This Server is Free":
                    continue
                await db_execute("DELETE FROM links WHERE uid=?", "DELETE FROM links WHERE uid=$1", (uid,))
                LINKS.pop(uid, None)
                await close_connections_for_link(uid)
    return {"ok": True}

@app.post("/api/links/{uid}/new-uuid")
async def regenerate_uuid(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if LINKS[uid].get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Cannot regenerate UUID for the default inbound.")
        new_uid = str(uuid_lib.uuid4())
        while new_uid in LINKS:
            new_uid = str(uuid_lib.uuid4())
        link = LINKS.pop(uid)
        link["uid"] = new_uid
        LINKS[new_uid] = link
        await db_execute("UPDATE links SET uid=? WHERE uid=?", "UPDATE links SET uid=$1 WHERE uid=$2", (new_uid, uid))
        async with connections_lock:
            to_update = [(cid, info) for cid, info in connections.items() if info.get("uuid") == uid]
            for cid, info in to_update:
                info["uuid"] = new_uid
            if uid in link_ip_map:
                link_ip_map[new_uid] = link_ip_map.pop(uid)
        log_event("Inbound", f"UUID regenerated for {link['label']}: {uid} -> {new_uid}")
        return {"new_uuid": new_uid}

@app.post("/api/links/{uid}/disconnect")
async def disconnect_link(uid: str, _=Depends(require_auth)):
    await close_connections_for_link(uid)
    log_event("Inbound", f"Disconnected all connections for {uid}")
    return {"ok": True}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        if link.get("label") == "This Server is Free":
            if "label" in body and body["label"].strip() != "This Server is Free":
                raise HTTPException(status_code=400, detail="Cannot rename the default system inbound.")
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
    updates = {}
    if "active" in body: updates["active"] = int(body["active"])
    if "limit_value" in body:
        limit_val = float(body.get("limit_value") or 0)
        unit = body.get("limit_unit") or "GB"
        updates["limit_bytes"] = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, unit)
    if "reset_usage" in body and body["reset_usage"]:
        updates["used_bytes"] = 0
    if "label" in body:
        new_label = str(body["label"])[:60]
        updates["label"] = new_label
    if "max_connections" in body:
        mc = int(body["max_connections"] or 0)
        updates["max_connections"] = mc if mc >= 0 else 0
    if "days_valid" in body:
        try:
            dv = int(body["days_valid"])
            if dv > 0: updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
            else: updates["expires_at"] = None
        except (ValueError, TypeError): pass
    if "custom_path" in body: updates["custom_path"] = str(body["custom_path"])[:100]
    if "custom_sni" in body: updates["custom_sni"] = str(body["custom_sni"])[:100]
    if "custom_host" in body: updates["custom_host"] = str(body["custom_host"])[:100]
    if "custom_fp" in body: updates["custom_fp"] = str(body["custom_fp"])[:20]
    if "color" in body: updates["color"] = str(body["color"])[:20]
    if "flag" in body:
        flag_val = str(body["flag"]).strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag_val):
            flag_val = ""
        else:
            flag_val = flag_val.upper()
        updates["flag"] = flag_val
    if "fragment" in body:
        updates["fragment"] = str(body["fragment"]).strip()[:50]
    if updates:
        async with LINKS_LOCK:
            link.update(updates)
        if DB_BACKEND == "sqlite":
            set_str = ", ".join(f"{k} = ?" for k in updates)
            vals = list(updates.values()) + [uid]
            await db_execute(f"UPDATE links SET {set_str} WHERE uid = ?", "", tuple(vals))
        else:
            set_str = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates))
            vals = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE links SET {set_str} WHERE uid = ${len(vals)}", tuple(vals))
    log_event("Inbound", f"Updated inbound {uid}")
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link and link.get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Default inbound (This Server is Free) cannot be deleted.")
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    log_event("Inbound", f"Deleted inbound {uid}")
    return {"ok": True}

# ═══ ADDRESSES ═══

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if addr in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(addr)
    try:
        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
    except ADDRESS_INTEGRITY_ERRORS:
        pass
    log_event("Clean IP", f"Added address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.patch("/api/addresses/{index}")
async def edit_address(index: int, request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_addr = (body.get("address") or "").strip()
    if not new_addr or not validate_address(new_addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            old = CUSTOM_ADDRESSES[index]
            if new_addr in CUSTOM_ADDRESSES and new_addr != old:
                raise HTTPException(status_code=400, detail="Address already exists")
            CUSTOM_ADDRESSES[index] = new_addr
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (old,))
            await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (new_addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Edited address from {old} to {new_addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
@limiter.limit("5/minute")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    added = 0
    errors = 0
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            if not addr or not validate_address(addr):
                errors += 1
                continue
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    try:
                        await db_execute("INSERT INTO custom_addresses (address) VALUES (?)", "INSERT INTO custom_addresses (address) VALUES ($1)", (addr,))
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
                    added += 1
                else:
                    errors += 1
    if added > 0:
        log_event("Clean IP", f"Batch added {added} addresses")
    return {"ok": True, "added": added, "errors": errors}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Deleted address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    log_event("Clean IP", "All addresses deleted")
    return {"ok": True}

@app.post("/api/addresses/bulk-delete")
async def bulk_delete_addresses(request: Request, _=Depends(require_auth)):
    body = await request.json()
    indices = body.get("indices", [])
    async with CUSTOM_ADDRESSES_LOCK:
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(CUSTOM_ADDRESSES):
                addr = CUSTOM_ADDRESSES.pop(idx)
                await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
    log_event("Clean IP", "Bulk deleted addresses")
    return {"ok": True}

# ═══ USER DASHBOARD & SUBSCRIPTION ═══

@app.get("/user/{uid}")
async def user_dashboard(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="User not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="User expired")
    status = "Active ✅"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "Quota Exceeded 🚫"
    elif expires and expires < datetime.now(timezone.utc):
        status = "Expired ⏰"
    elif not link["active"]:
        status = "Blocked 🔒"
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    usage_percent = 0 if limit == 0 else min(100, round(used / limit * 100, 1))
    usage_bar_color = "#4ade80" if usage_percent < 80 else ("#fbbf24" if usage_percent < 95 else "#f87171")
    vless_link = generate_vless_link(uid, remark=link["label"])
    sub_url = f"https://{get_domain()}/sub/{uid}"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={quote(sub_url)}"
    expiry_str = "Unlimited ∞" if not expires else expires.strftime("%Y-%m-%d %H:%M (UTC)")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Dashboard | {link['label']}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:#0a0a0a;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}}
.card{{background:rgba(20,20,20,0.9);border:1px solid rgba(57,255,20,0.15);border-radius:24px;padding:36px 24px;max-width:420px;width:100%;box-shadow:0 0 40px rgba(57,255,20,0.1);text-align:center;}}
h1{{color:#39ff14;font-size:1.8rem;margin-bottom:8px;font-weight:800;}}
.subtitle{{color:#a0a0a0;font-size:0.9rem;margin-bottom:24px;}}
.info-box{{background:rgba(255,255,255,0.03);border-radius:16px;padding:16px;margin-bottom:24px;text-align:left;}}
.row{{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:0.95rem;}}
.row:last-child{{border-bottom:none;}}
.label{{color:#888;font-weight:600;}}
.value{{color:#fff;font-weight:600;}}
.progress-bar-bg{{height:8px;background:rgba(255,255,255,0.1);border-radius:4px;margin-top:12px;overflow:hidden;}}
.progress-bar-fill{{height:100%;width:{usage_percent}%;background:{usage_bar_color};border-radius:4px;transition:width 0.3s;}}
.progress-text{{font-size:0.8rem;color:#aaa;margin-top:4px;text-align:right;}}
.qr{{background:#fff;padding:12px;border-radius:16px;display:inline-block;margin-bottom:24px;}}
.qr img{{display:block;border-radius:8px;}}
.btn{{display:flex;align-items:center;justify-content:center;width:100%;padding:14px;background:linear-gradient(135deg,#39ff14,#1a8c1a);color:#000;font-weight:800;border-radius:12px;text-decoration:none;transition:all 0.2s;margin-bottom:12px;border:none;cursor:pointer;font-family:inherit;font-size:1rem;}}
.btn:hover{{filter:brightness(1.1);box-shadow:0 0 20px rgba(57,255,20,0.3);}}
.btn-outline{{background:transparent;color:#39ff14;border:2px solid rgba(57,255,20,0.3);}}
.btn-outline:hover{{background:rgba(57,255,20,0.1);box-shadow:none;}}
#toast{{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#39ff14;color:#000;padding:10px 20px;border-radius:30px;font-weight:700;opacity:0;transition:opacity 0.3s;pointer-events:none;}}
</style>
</head>
<body>
<div class="card">
    <h1>{link['label']}</h1>
    <div class="subtitle">Secure Subscription Dashboard</div>
    <div class="info-box">
        <div class="row"><span class="label">Status</span><span class="value">{status}</span></div>
        <div class="row"><span class="label">Data Usage</span><span class="value">{_fmt_bytes(used)} / {'∞' if limit == 0 else _fmt_bytes(limit)}</span></div>
        <div class="progress-bar-bg"><div class="progress-bar-fill"></div></div>
        <div class="progress-text">{usage_percent}% used</div>
        <div class="row"><span class="label">Expiration</span><span class="value">{expiry_str}</span></div>
    </div>
    <div class="qr">
        <img src="{qr_url}" alt="Scan to Import" width="200" height="200">
    </div>
    <button class="btn" onclick="copyToClip('{sub_url}', 'Subscription Link Copied!')">🔗 Copy Subscription Link</button>
    <button class="btn btn-outline" onclick="copyToClip('{vless_link}', 'VLESS Link Copied!')">📋 Copy Single VLESS Link</button>
</div>
<div id="toast">Copied!</div>
<script>
function copyToClip(text, msg) {{
    navigator.clipboard.writeText(text).then(() => {{
        const toast = document.getElementById('toast');
        toast.innerText = msg;
        toast.style.opacity = '1';
        setTimeout(() => toast.style.opacity = '0', 2500);
    }});
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/user/{uid}/sub")
@limiter.limit("10/minute")
async def user_subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="link expired")
    status = "active"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "quota_exceeded"
    elif expires and expires < datetime.now(timezone.utc):
        status = "expired"
    elif not link["active"]:
        status = "blocked"
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    extra = {
        "custom_path": link.get("custom_path", ""),
        "custom_sni": link.get("custom_sni", ""),
        "custom_host": link.get("custom_host", ""),
        "custom_fp": link.get("custom_fp", "chrome"),
        "fragment": link.get("fragment", ""),
    }
    sub_content = generate_subscription_content(link, uid, addresses, extra, status)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires.timestamp()) if expires else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
        "X-Status": status,
    }
    log_event("Subscription", f"Subscription accessed for {link['label']} ({uid}) status={status}", ip=request.client.host)
    return Response(content=encoded, headers=headers)

@app.get("/sub/{uid}")
@limiter.limit("10/minute")
async def subscription_endpoint(uid: str, request: Request):
    return await user_subscription(uid, request)

def generate_subscription_content(link: dict, uid: str, addresses: list, extra: dict = None, status: str = "active") -> str:
    used = link["used_bytes"]; limit = link["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(link.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_remark = ""
    if status == "quota_exceeded":
        status_remark = "🚫 Quota Exceeded"
    elif status == "expired":
        status_remark = "⏰ Expired"
    elif status == "blocked":
        status_remark = "🔒 Blocked"
    full_remark = f"📊 {usage_str} | ⏳ {expiry_str}"
    if status_remark:
        full_remark += f" | {status_remark}"
    flag_emoji = code_to_flag(link.get("flag", ""))
    if flag_emoji:
        full_remark = flag_emoji + " " + full_remark
    status_node = generate_vless_link(uid, remark=full_remark, address="0.0.0.0", extra=extra)
    server_node = generate_vless_link(uid, remark=f"{flag_emoji}This Service is Free" if flag_emoji else "This Service is Free", extra=extra)
    links = [status_node, server_node]
    for i, addr in enumerate(addresses):
        links.append(generate_vless_link(uid, remark=f"{flag_emoji}SulgX-{link['label']}-IP{i+1}" if flag_emoji else f"SulgX-{link['label']}-IP{i+1}", address=addr, extra=extra))
    return "\n".join(links)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

# ═══ SCANNER ═══

@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    await websocket.accept()
    tasks = []
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        if not isinstance(items, list) or len(items) == 0:
            await websocket.close()
            return
        max_ips = 256
        max_row = await db_fetchone("SELECT value FROM settings WHERE key='max_scan_ips'", "SELECT value FROM settings WHERE key='max_scan_ips'")
        if max_row and max_row["value"]:
            try: max_ips = int(max_row["value"])
            except: pass
        if len(items) > max_ips:
            await websocket.send_json({"done": True, "error": f"Maximum {max_ips} IPs allowed."})
            return
        timeout_str = "4"
        row = await db_fetchone("SELECT value FROM settings WHERE key='scanner_timeout'", "SELECT value FROM settings WHERE key='scanner_timeout'")
        if row and row["value"]:
            timeout_str = row["value"]
        try:
            timeout = float(timeout_str)
            if timeout <= 0: timeout = 4
        except:
            timeout = 4
        sem = asyncio.Semaphore(20)
        async def scan_one(item):
            async with sem:
                ip_str = str(item).strip()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        await websocket.send_json({"ip": ip_str, "ok": False, "latency": None})
                        return
                except ValueError:
                    pass
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            resp = await client.get(f"https://{ip_str}:443", follow_redirects=True)
                        latency = round((time.time() - start) * 1000)
                        result = {"ip": ip_str, "ok": True, "latency": latency}
                    except:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=timeout)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        result = {"ip": ip_str, "ok": True, "latency": latency}
                except Exception:
                    result = {"ip": ip_str, "ok": False, "latency": None}
                await websocket.send_json(result)
        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        await asyncio.gather(*tasks)
        await websocket.send_json({"done": True})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Scanner WS error: {e}")
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Scanner WS: {e}", "type": "Scanner"})
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        try:
            await websocket.close()
        except Exception:
            pass

# ═══ TUNNEL ═══

RELAY_BUF = 512 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24: 
        raise ValueError("VLESS header chunk too small for parsing")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    if len(first_chunk) < pos + 3:
        raise ValueError("Malformed VLESS header structure")
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        if len(first_chunk) < pos + 4: 
            raise ValueError("Incomplete IPv4 address bytes")
        addr_bytes = first_chunk[pos:pos+4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        if len(first_chunk) < pos + 1: 
            raise ValueError("Missing domain name length indicator")
        domain_len = first_chunk[pos]
        pos += 1
        if len(first_chunk) < pos + domain_len: 
            raise ValueError("Incomplete domain name bytes")
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(first_chunk) < pos + 16: 
            raise ValueError("Incomplete IPv6 address bytes")
        addr_bytes = first_chunk[pos:pos+16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else: 
        raise ValueError(f"Unsupported VLESS address type identifier: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            link = LINKS[uid]
            link["used_bytes"] += n
            limit = link["limit_bytes"]
            if limit > 0 and link["used_bytes"] >= limit * 0.9 and (link["used_bytes"] - n) < limit * 0.9:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 90% of quota")
                await notify_telegram_event("quota_90", link["label"], uid)
            elif limit > 0 and link["used_bytes"] >= limit * 0.8 and (link["used_bytes"] - n) < limit * 0.8:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 80% of quota")

async def notify_telegram_event(event: str, label: str, uid: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    if lang == 'fa':
        default_msg = f"رویداد: {event} برای {label}"
    else:
        default_msg = f"Event: {event} for {label}"
    msg = templates.get(event, default_msg)
    msg = msg.replace("{label}", label).replace("{uid}", uid)
    panel_url = f"https://{get_domain()}/panel"
    msg += f'\n\n<a href="{panel_url}">Open Best Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except: pass

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["upload_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"ws_to_tcp error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"ws_to_tcp {conn_id}: {e}", "type": "Tunnel"})
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except Exception: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                log_event("Tunnel", f"Quota exceeded for {link_uid}")
                break
            stats["total_bytes"] += size; stats["download_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size)
            await add_usage(link_uid, size)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e:
        logger.error(f"tcp_to_ws error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"tcp_to_ws {conn_id}: {e}", "type": "Tunnel"})

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WS accepted {uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link or not link["active"]:
                await websocket.close(code=1008, reason="not found or disabled")
                log_event("Tunnel", f"Inactive/not found uuid {uuid}", ip=client_ip)
                return
            max_conn = link.get("max_connections", 0)
        expires = parse_expires_at(link.get("expires_at"))
        if expires and expires < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="expired")
            log_event("Tunnel", f"Expired uuid {uuid}", ip=client_ip)
            return
        if max_conn > 0:
            if await count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="connection limit")
                log_event("Tunnel", f"Connection limit reached for {uuid}", ip=client_ip)
                return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        try: command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
            await websocket.close(code=1008, reason="invalid header")
            log_event("Tunnel", f"Invalid header from {client_ip}: {e}")
            return
        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now(timezone.utc).isoformat(), "bytes": 0, "last_active": now}
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)
        stats["total_requests"] += 1
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size; stats["upload_bytes"] += p_size
            await add_usage(uuid, p_size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.get_extra_info('socket')
        if sock: sock.setsockopt(6, 1, 1)
        if initial_payload:
            try: writer.write(initial_payload); await writer.drain()
            except Exception: pass
        up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel(); await t
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Tunnel {uuid}: {exc}", "type": "WebSocket"})
        logger.exception("WS error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip:
                        if not any(c.get("uuid")==uid and c.get("ip")==ip for c in connections.values()):
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]: link_ip_map.pop(uid, None)

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"


# ═══ BEST PANEL EXTRA CAPABILITIES ═══

@app.get("/api/system/report")
async def api_system_report(_=Depends(require_auth)):
    """Compact operational report for dashboard/tools."""
    async with LINKS_LOCK:
        links = list(LINKS.values())
    async with connections_lock:
        active_connections = len(connections)

    now = datetime.now(timezone.utc)
    total_limit = sum(int(l.get("limit_bytes") or 0) for l in links)
    total_used = sum(int(l.get("used_bytes") or 0) for l in links)

    expired = 0
    quota_full = 0
    active_links = 0
    inactive_links = 0

    for l in links:
        if l.get("active"):
            active_links += 1
        else:
            inactive_links += 1

        exp = parse_expires_at(l.get("expires_at"))
        if exp and exp < now:
            expired += 1

        lim = int(l.get("limit_bytes") or 0)
        used = int(l.get("used_bytes") or 0)
        if lim > 0 and used >= lim:
            quota_full += 1

    return {
        "brand": "Best Panel",
        "domain": get_domain(),
        "uptime": uptime(),
        "db_backend": DB_BACKEND,
        "links_total": len(links),
        "links_active": active_links,
        "links_inactive": inactive_links,
        "links_expired": expired,
        "links_quota_full": quota_full,
        "active_connections": active_connections,
        "traffic_total_bytes": stats["total_bytes"],
        "traffic_upload_bytes": stats["upload_bytes"],
        "traffic_download_bytes": stats["download_bytes"],
        "links_used_bytes": total_used,
        "links_limit_bytes": total_limit,
        "errors": stats["total_errors"],
        "requests": stats["total_requests"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/links/{uid}/clone")
async def clone_link(uid: str, request: Request, _=Depends(require_auth)):
    """Clone an inbound with a new UUID while keeping limits/options."""
    body = await request.json()
    async with LINKS_LOCK:
        src_link = LINKS.get(uid)
        if not src_link:
            raise HTTPException(status_code=404, detail="link not found")

        new_uid = str(uuid_lib.uuid4())
        while new_uid in LINKS:
            new_uid = str(uuid_lib.uuid4())

        now = datetime.now(timezone.utc).isoformat()
        new_label = str(body.get("label") or (src_link.get("label", "Clone") + " Copy"))[:60]

        cloned = dict(src_link)
        cloned.update({
            "uid": new_uid,
            "label": new_label,
            "used_bytes": 0,
            "created_at": now,
            "active": 1,
        })
        LINKS[new_uid] = cloned

    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        (
            cloned["uid"],
            cloned["label"],
            int(cloned.get("limit_bytes") or 0),
            0,
            int(cloned.get("max_connections") or 0),
            now,
            1,
            cloned.get("expires_at"),
            cloned.get("custom_path", ""),
            cloned.get("custom_sni", ""),
            cloned.get("custom_host", ""),
            cloned.get("custom_fp", "chrome"),
            cloned.get("color", "#39ff14"),
            cloned.get("flag", ""),
            cloned.get("fragment", ""),
        ),
    )

    log_event("Inbound", f"Cloned inbound {uid} -> {new_uid}")
    return {"ok": True, "uuid": new_uid, "label": new_label}


@app.patch("/api/links/{uid}/usage")
async def set_link_usage(uid: str, request: Request, _=Depends(require_auth)):
    """Manually set used traffic for an inbound."""
    body = await request.json()
    value = float(body.get("value") or 0)
    unit = str(body.get("unit") or "GB").upper()
    used_bytes = max(0, parse_size_to_bytes(value, unit))

    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        link["used_bytes"] = used_bytes

    await db_execute(
        "UPDATE links SET used_bytes = ? WHERE uid = ?",
        "UPDATE links SET used_bytes = $1 WHERE uid = $2",
        (used_bytes, uid),
    )

    log_event("Inbound", f"Manual usage set for {uid}: {used_bytes} bytes")
    return {"ok": True, "used_bytes": used_bytes}


@app.post("/api/quick/maintenance")
async def quick_maintenance(request: Request, _=Depends(require_auth)):
    """Run quick maintenance actions from the UI."""
    body = await request.json()
    action = str(body.get("action") or "")
    changed = 0
    now = datetime.now(timezone.utc)

    if action == "deactivate_expired":
        async with LINKS_LOCK:
            for uid, link in LINKS.items():
                exp = parse_expires_at(link.get("expires_at"))
                if exp and exp < now and link.get("active"):
                    link["active"] = 0
                    changed += 1
                    await db_execute(
                        "UPDATE links SET active = 0 WHERE uid = ?",
                        "UPDATE links SET active = FALSE WHERE uid = $1",
                        (uid,),
                    )
                    await close_connections_for_link(uid)

    elif action == "reset_inactive_usage":
        async with LINKS_LOCK:
            for uid, link in LINKS.items():
                if not link.get("active") and int(link.get("used_bytes") or 0) > 0:
                    link["used_bytes"] = 0
                    changed += 1
                    await db_execute(
                        "UPDATE links SET used_bytes = 0 WHERE uid = ?",
                        "UPDATE links SET used_bytes = 0 WHERE uid = $1",
                        (uid,),
                    )

    elif action == "clear_runtime_logs":
        changed = len(error_logs)
        error_logs.clear()

    else:
        raise HTTPException(status_code=400, detail="Unknown maintenance action")

    log_event("Maintenance", f"Quick action executed: {action}, changed={changed}")
    return {"ok": True, "action": action, "changed": changed}


# ── HTML Panel v1.1.0 ───────────────────────────────────────────────
PANEL_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Best Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&family=Inter:wght@400;500;600;700;800&family=Vazirmatn:wght@400;500;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#07111f;
  --bg2:#0b1728;
  --bg3:#0f2035;
  --glass:rgba(255,255,255,.08);
  --glass2:rgba(255,255,255,.06);
  --line:rgba(255,255,255,.12);
  --text:#eaf4ff;
  --muted:#9cb4cf;
  --primary:#6ee7ff;
  --primary2:#7c3aed;
  --success:#4ade80;
  --warn:#fbbf24;
  --danger:#f87171;
  --shadow:0 10px 35px rgba(0,0,0,.35);
  --radius:22px;
  --radius2:16px;
}
body.light-mode{
  --bg:#eef6ff;
  --bg2:#f7fbff;
  --bg3:#ffffff;
  --glass:rgba(255,255,255,.75);
  --glass2:rgba(255,255,255,.55);
  --line:rgba(20,40,80,.10);
  --text:#102033;
  --muted:#58708d;
  --primary:#0ea5e9;
  --primary2:#7c3aed;
  --shadow:0 10px 30px rgba(20,40,80,.12);
}
body.blue-mode{
  --bg:#030712;
  --bg2:#0b1120;
  --bg3:#111827;
  --glass:rgba(30,41,59,.55);
  --glass2:rgba(30,41,59,.45);
  --line:rgba(125,211,252,.12);
  --text:#e5f3ff;
  --muted:#96abc4;
  --primary:#38bdf8;
  --primary2:#818cf8;
  --shadow:0 14px 34px rgba(0,0,0,.45);
}
html,body{height:100%;overflow-x:hidden}
body{
  font-family:'Inter','Vazirmatn',sans-serif;
  color:var(--text);
  background:
    radial-gradient(circle at top left, rgba(124,58,237,.22), transparent 28%),
    radial-gradient(circle at top right, rgba(56,189,248,.18), transparent 30%),
    linear-gradient(180deg,var(--bg),var(--bg2) 45%,var(--bg3));
}
body[dir="rtl"]{direction:rtl}
body[dir="rtl"] .side{right:0;left:auto}
body[dir="rtl"] .content{margin-right:280px;margin-left:0}
body[dir="rtl"] .topbar{left:24px;right:304px}
a{text-decoration:none;color:inherit}
button,input,select,textarea{font-family:inherit}
.bg-orb{
  position:fixed;inset:auto;
  width:380px;height:380px;border-radius:50%;
  filter:blur(60px);opacity:.18;pointer-events:none;z-index:0
}
.orb1{top:-80px;left:-80px;background:var(--primary)}
.orb2{bottom:-100px;right:-60px;background:var(--primary2)}
#login-page,#dashboard-page{position:relative;z-index:1}
.glass{
  background:var(--glass);
  border:1px solid var(--line);
  backdrop-filter:blur(18px);
  -webkit-backdrop-filter:blur(18px);
  box-shadow:var(--shadow);
}
.side{
  position:fixed;left:0;top:0;bottom:0;width:280px;padding:22px 18px;
  border-right:1px solid var(--line);
  background:linear-gradient(180deg,rgba(255,255,255,.08),rgba(255,255,255,.03));
  backdrop-filter:blur(18px);z-index:40
}
.brand{
  display:flex;align-items:center;gap:12px;padding:14px 14px 18px;margin-bottom:10px
}
.brand-logo{
  width:50px;height:50px;border-radius:18px;
  display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,var(--primary),var(--primary2));
  color:#fff;font-weight:900;font-size:1.1rem;
  box-shadow:0 10px 24px rgba(56,189,248,.35)
}
.brand-text h1{
  font-family:'Orbitron',sans-serif;
  font-size:1.15rem;letter-spacing:.05em
}
.brand-text p{font-size:.8rem;color:var(--muted);margin-top:4px}
.nav{
  display:flex;flex-direction:column;gap:8px;margin-top:14px
}
.nav-link{
  border:none;background:transparent;color:var(--muted);cursor:pointer;
  display:flex;align-items:center;gap:12px;width:100%;
  padding:14px 16px;border-radius:16px;font-weight:700;font-size:.95rem;
  transition:.22s
}
.nav-link:hover{
  background:rgba(255,255,255,.08);
  color:var(--text);transform:translateX(2px)
}
.nav-link.active{
  color:#fff;
  background:linear-gradient(135deg,rgba(56,189,248,.35),rgba(124,58,237,.32));
  border:1px solid rgba(255,255,255,.12)
}
.side-bottom{
  position:absolute;left:18px;right:18px;bottom:18px
}
.mini-card{
  padding:14px;border-radius:18px;
  background:rgba(255,255,255,.06);border:1px solid var(--line)
}
.mini-card .k{font-size:.78rem;color:var(--muted)}
.mini-card .v{font-size:1.05rem;font-weight:800;margin-top:6px}
.content{
  margin-left:280px;min-height:100vh;padding:24px
}
.topbar{
  position:sticky;top:20px;z-index:30;
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:16px 18px;border-radius:22px;margin-bottom:18px
}
.top-left h2{font-size:1.15rem;font-weight:800}
.top-left p{font-size:.85rem;color:var(--muted);margin-top:4px}
.top-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.btn,.btn2,.icon-btn{
  border:none;cursor:pointer;transition:.2s
}
.btn{
  padding:12px 16px;border-radius:14px;font-weight:800;
  background:linear-gradient(135deg,var(--primary),var(--primary2));
  color:#fff;box-shadow:0 10px 24px rgba(56,189,248,.28)
}
.btn:hover{transform:translateY(-1px);filter:brightness(1.05)}
.btn2{
  padding:11px 14px;border-radius:14px;font-weight:700;
  background:rgba(255,255,255,.07);color:var(--text);
  border:1px solid var(--line)
}
.btn-danger{
  background:rgba(248,113,113,.12)!important;
  color:var(--danger)!important;border:1px solid rgba(248,113,113,.22)!important
}
.icon-btn{
  width:42px;height:42px;border-radius:14px;
  background:rgba(255,255,255,.07);color:var(--text);
  border:1px solid var(--line)
}
.stats{
  display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:16px
}
.stat{
  padding:18px;border-radius:22px;position:relative;overflow:hidden
}
.stat::after{
  content:"";position:absolute;right:-20px;top:-20px;width:90px;height:90px;border-radius:50%;
  background:radial-gradient(circle, rgba(255,255,255,.20), transparent 60%)
}
.stat .label{font-size:.78rem;color:var(--muted);font-weight:800;text-transform:uppercase}
.stat .value{font-size:1.6rem;font-weight:900;margin-top:10px}
.stat .sub{font-size:.82rem;color:var(--muted);margin-top:6px}
.grid-2{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;margin-bottom:16px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.card{
  padding:18px;border-radius:22px
}
.card-head{
  display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:14px
}
.card-title{font-size:1rem;font-weight:800}
.card-sub{font-size:.82rem;color:var(--muted)}
.chart-wrap{height:260px}
.list{
  display:flex;flex-direction:column;gap:12px
}
.list-row{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:12px 14px;border-radius:16px;background:rgba(255,255,255,.05);border:1px solid var(--line)
}
.k{color:var(--muted);font-size:.9rem}
.v{font-weight:800}
.page{display:none}
.page.active{display:block;animation:fade .28s ease}
@keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.tools{
  display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px
}
.search{
  flex:1;min-width:220px;padding:13px 14px;border-radius:16px;
  background:rgba(255,255,255,.06);border:1px solid var(--line);color:var(--text);outline:none
}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{
  padding:10px 14px;border-radius:14px;border:1px solid var(--line);
  background:rgba(255,255,255,.05);color:var(--muted);cursor:pointer;font-weight:700
}
.chip.active{background:linear-gradient(135deg,rgba(56,189,248,.25),rgba(124,58,237,.25));color:#fff}
.table-card{padding:0;overflow:hidden}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:14px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:.9rem}
th{font-size:.76rem;text-transform:uppercase;color:var(--muted);font-weight:800;letter-spacing:.06em;position:sticky;top:0;background:rgba(11,23,40,.88);backdrop-filter:blur(12px)}
body.light-mode th{background:rgba(255,255,255,.82)}
tr:hover td{background:rgba(255,255,255,.035)}
.badge{
  display:inline-flex;align-items:center;gap:6px;
  padding:8px 10px;border-radius:999px;font-size:.75rem;font-weight:800
}
.on{background:rgba(74,222,128,.12);color:var(--success);border:1px solid rgba(74,222,128,.22)}
.off{background:rgba(248,113,113,.12);color:var(--danger);border:1px solid rgba(248,113,113,.22)}
.type{background:rgba(56,189,248,.12);color:var(--primary);border:1px solid rgba(56,189,248,.22)}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.a-btn{
  border:none;cursor:pointer;padding:8px 10px;border-radius:12px;
  background:rgba(255,255,255,.07);color:var(--text);border:1px solid var(--line);font-weight:700
}
.a-btn.danger{color:var(--danger)}
.a-btn.ok{color:var(--success)}
.a-btn.warn{color:var(--warn)}
.progress{
  width:160px;height:8px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;margin-top:8px
}
.progress > span{display:block;height:100%;border-radius:999px}
.empty{
  padding:28px;text-align:center;color:var(--muted)
}
.form-grid{
  display:grid;grid-template-columns:1fr 1fr;gap:14px
}
.fg{display:flex;flex-direction:column;gap:7px;margin-bottom:14px}
label{font-size:.84rem;color:var(--muted);font-weight:700}
input,select,textarea{
  width:100%;padding:13px 14px;border-radius:16px;outline:none;color:var(--text);
  background:rgba(255,255,255,.06);border:1px solid var(--line)
}
textarea{min-height:110px;resize:vertical}
.modal{
  position:fixed;inset:0;background:rgba(2,8,20,.52);
  display:none;align-items:center;justify-content:center;z-index:100;
  backdrop-filter:blur(8px)
}
.modal.show{display:flex}
.modal-box{
  width:min(720px,92vw);max-height:90vh;overflow:auto;
  padding:20px;border-radius:26px
}
.modal-head{
  display:flex;align-items:center;justify-content:space-between;margin-bottom:14px
}
.modal-title{font-size:1.15rem;font-weight:900}
.close{
  width:40px;height:40px;border:none;border-radius:14px;cursor:pointer;
  background:rgba(255,255,255,.08);color:var(--text);border:1px solid var(--line)
}
.toast{
  position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(16px);
  padding:14px 20px;border-radius:16px;background:rgba(15,23,42,.92);color:#fff;
  border:1px solid rgba(255,255,255,.12);opacity:0;pointer-events:none;transition:.25s;z-index:200
}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.footer{
  margin-top:18px;padding:16px 18px;border-radius:18px;
  display:flex;justify-content:center;gap:18px;flex-wrap:wrap;font-size:.88rem;color:var(--muted)
}
.footer a{color:var(--primary);font-weight:700}
.mobile-bar{display:none}
.lang-switch{display:flex;gap:6px}
.lang-switch button{
  padding:10px 12px;border-radius:12px;border:1px solid var(--line);
  background:rgba(255,255,255,.06);color:var(--text);cursor:pointer;font-weight:800
}
.lang-switch button.active{background:linear-gradient(135deg,rgba(56,189,248,.28),rgba(124,58,237,.28))}
.kpi-mini{
  display:grid;grid-template-columns:1fr 1fr;gap:12px
}
.qrbox{
  text-align:center;padding:16px;border-radius:18px;background:rgba(255,255,255,.05);border:1px solid var(--line)
}
.qrbox img{max-width:220px;border-radius:18px}
.toggle{
  width:48px;height:28px;border-radius:999px;background:rgba(255,255,255,.10);
  border:1px solid var(--line);position:relative;cursor:pointer
}
.toggle:after{
  content:"";position:absolute;top:3px;left:4px;width:20px;height:20px;border-radius:50%;
  background:#fff;transition:.22s
}
.toggle.on{background:rgba(74,222,128,.35)}
.toggle.on:after{left:22px}
@media(max-width:1200px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .grid-2,.grid-3{grid-template-columns:1fr}
}
@media(max-width:900px){
  .side{display:none}
  .content{margin-left:0;padding:16px 16px 90px}
  body[dir="rtl"] .content{margin-right:0}
  .topbar{position:relative;top:0;left:0;right:0}
  .mobile-bar{
    display:flex;position:fixed;left:10px;right:10px;bottom:10px;z-index:60;
    padding:10px;border-radius:20px;justify-content:space-between;gap:8px
  }
  .mobile-item{
    flex:1;padding:10px 6px;border:none;border-radius:14px;background:transparent;color:var(--muted);font-size:.78rem;font-weight:800;cursor:pointer
  }
  .mobile-item.active{
    background:linear-gradient(135deg,rgba(56,189,248,.24),rgba(124,58,237,.24));color:#fff
  }
}
@media(max-width:640px){
  .stats{grid-template-columns:1fr}
  .form-grid{grid-template-columns:1fr}
  .top-right{justify-content:flex-start}
}
</style>
</head>
<body>
<div class="bg-orb orb1"></div>
<div class="bg-orb orb2"></div>
<div class="toast" id="toast"></div>

<div id="login-page" style="display:none">
  <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px">
    <div class="glass" style="width:min(460px,95vw);padding:30px;border-radius:30px">
      <div style="text-align:center;margin-bottom:22px">
        <div style="display:inline-flex;width:84px;height:84px;border-radius:26px;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--primary),var(--primary2));font-family:'Orbitron';font-size:1.2rem;font-weight:900;color:#fff;box-shadow:0 14px 34px rgba(56,189,248,.35)">BP</div>
        <h1 style="font-family:'Orbitron';font-size:1.8rem;margin-top:16px">Best Panel</h1>
        <p style="color:var(--muted);margin-top:8px" data-en="Secure access to your control center" data-fa="ورود امن به مرکز کنترل شما">Secure access to your control center</p>
      </div>
      <div class="fg">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <input type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <button class="btn" style="width:100%;margin-top:10px" onclick="doLogin()" data-en="Login" data-fa="ورود">Login</button>
      <div id="login-err" style="display:none;margin-top:12px;color:var(--danger);font-weight:700;text-align:center">Invalid password</div>
      <div id="login-custom-message" style="margin-top:18px;color:var(--muted);text-align:center;font-size:.92rem"></div>
    </div>
  </div>
</div>

<div id="dashboard-page" style="display:none">
  <aside class="side glass">
    <div class="brand">
      <div class="brand-logo">BP</div>
      <div class="brand-text">
        <h1>Best Panel</h1>
        <p>Glass Control Center</p>
      </div>
    </div>

    <div class="nav" id="mainNav">
      <button class="nav-link active" data-page="dashboard">📊 <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span></button>
      <button class="nav-link" data-page="inbounds">📡 <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span></button>
      <button class="nav-link" data-page="addresses">🌐 <span data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span></button>
      <button class="nav-link" data-page="ipscanner">🔎 <span data-en="Scanner" data-fa="اسکنر">Scanner</span></button>
      <button class="nav-link" data-page="logs">🧾 <span data-en="Logs" data-fa="لاگ‌ها">Logs</span></button>
      <button class="nav-link" data-page="telegram">🤖 <span data-en="Telegram" data-fa="تلگرام">Telegram</span></button>
      <button class="nav-link" data-page="settings">⚙️ <span data-en="Settings" data-fa="تنظیمات">Settings</span></button>
    </div>

    <div class="side-bottom">
      <div class="mini-card">
        <div class="k" data-en="Live Uptime" data-fa="آپتایم زنده">Live Uptime</div>
        <div class="v" id="sidebar-uptime">--:--:--</div>
      </div>
    </div>
  </aside>

  <main class="content">
    <div class="topbar glass">
      <div class="top-left">
        <h2>Best Panel</h2>
        <p id="last-up">Ready</p>
      </div>
      <div class="top-right">
        <button class="btn2" onclick="randomInbound()">+ Random</button>
        <div class="lang-switch">
          <button class="lang-en active" onclick="setLang('en')">EN</button>
          <button class="lang-fa" onclick="setLang('fa')">FA</button>
        </div>
        <button class="icon-btn" onclick="toggleTheme()">🌓</button>
        <button class="btn2 btn-danger" onclick="doLogout()" data-en="Logout" data-fa="خروج">Logout</button>
      </div>
    </div>

    <section class="page active" id="page-dashboard">
      <div class="stats">
        <div class="stat glass">
          <div class="label" data-en="Traffic" data-fa="ترافیک">Traffic</div>
          <div class="value" id="sv-traffic">--</div>
          <div class="sub" data-en="Total processed traffic" data-fa="کل ترافیک پردازش‌شده">Total processed traffic</div>
        </div>
        <div class="stat glass">
          <div class="label" data-en="Requests" data-fa="درخواست‌ها">Requests</div>
          <div class="value" id="sv-requests">--</div>
          <div class="sub" data-en="Total tunnel requests" data-fa="کل درخواست‌های تونل">Total tunnel requests</div>
        </div>
        <div class="stat glass">
          <div class="label" data-en="Connections" data-fa="اتصالات">Connections</div>
          <div class="value" id="sv-conns">--</div>
          <div class="sub" data-en="Current active sessions" data-fa="سشن‌های فعال فعلی">Current active sessions</div>
        </div>
        <div class="stat glass">
          <div class="label" data-en="Disk Free" data-fa="فضای آزاد">Disk Free</div>
          <div class="value" id="sv-disk">--</div>
          <div class="sub" data-en="Available storage" data-fa="فضای ذخیره‌سازی در دسترس">Available storage</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card glass">
          <div class="card-head">
            <div>
              <div class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</div>
              <div class="card-sub" data-en="Today traffic analytics" data-fa="تحلیل ترافیک امروز">Today traffic analytics</div>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="tc"></canvas></div>
        </div>

        <div class="card glass">
          <div class="card-head">
            <div>
              <div class="card-title" data-en="System Status" data-fa="وضعیت سیستم">System Status</div>
              <div class="card-sub" data-en="Realtime resource usage" data-fa="مصرف لحظه‌ای منابع">Realtime resource usage</div>
            </div>
          </div>
          <div class="list">
            <div class="list-row"><span class="k">CPU</span><span class="v" id="cpu-v">--%</span></div>
            <div class="progress"><span id="cpu-b" style="width:0;background:linear-gradient(90deg,var(--primary),var(--primary2))"></span></div>
            <div class="list-row"><span class="k">Memory</span><span class="v" id="mem-v">--%</span></div>
            <div class="progress"><span id="mem-b" style="width:0;background:linear-gradient(90deg,var(--success),var(--primary))"></span></div>
            <div class="list-row"><span class="k">Download</span><span class="v" id="sv-down-speed">--</span></div>
            <div class="list-row"><span class="k">Upload</span><span class="v" id="sv-up-speed">--</span></div>
            <div class="list-row"><span class="k">Monthly</span><span class="v" id="sv-monthly">--</span></div>
            <div class="list-row"><span class="k">Uptime</span><span class="v" id="sv-uptime">--</span></div>
          </div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card glass">
          <div class="card-head">
            <div>
              <div class="card-title" data-en="Usage Distribution" data-fa="توزیع مصرف">Usage Distribution</div>
              <div class="card-sub" data-en="Inbound usage split" data-fa="تقسیم مصرف اینباندها">Inbound usage split</div>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="doughnut-chart"></canvas></div>
        </div>

        <div class="card glass">
          <div class="card-head">
            <div>
              <div class="card-title" data-en="Live Speed" data-fa="سرعت زنده">Live Speed</div>
              <div class="card-sub" data-en="Realtime upload/download" data-fa="آپلود/دانلود لحظه‌ای">Realtime upload/download</div>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="speed-chart"></canvas></div>
        </div>
      </div>

      <div class="card glass">
        <div class="card-head">
          <div>
            <div class="card-title" data-en="Recent Activity" data-fa="فعالیت‌های اخیر">Recent Activity</div>
            <div class="card-sub" data-en="Latest panel logins" data-fa="آخرین ورودهای پنل">Latest panel logins</div>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th data-en="Time" data-fa="زمان">Time</th><th data-en="IP / Agent" data-fa="آی‌پی / عامل">IP / Agent</th><th data-en="Status" data-fa="وضعیت">Status</th></tr></thead>
            <tbody id="login-logs-tbody"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="page" id="page-inbounds">
      <div class="tools">
        <input class="search" id="srch" placeholder="Search inbounds..." oninput="filterLinks()">
        <div class="chips">
          <button class="chip active" onclick="setFilter('all',this)">All</button>
          <button class="chip" onclick="setFilter('active',this)">Active</button>
          <button class="chip" onclick="setFilter('off',this)">Off</button>
        </div>
        <button class="btn" onclick="showAddMo()">+ Create</button>
      </div>

      <div class="tools">
        <button class="btn2" onclick="batchAction('activate')">Activate</button>
        <button class="btn2" onclick="batchAction('deactivate')">Deactivate</button>
        <button class="btn2" onclick="batchAction('reset_usage')">Reset Usage</button>
        <button class="btn2 btn-danger" onclick="batchAction('delete')">Delete</button>
        <button class="btn2" onclick="exportLinks()">Export</button>
        <button class="btn2" onclick="document.getElementById('import-file').click()">Import</button>
        <input type="file" id="import-file" style="display:none" accept=".json" onchange="importLinks(this)">
      </div>

      <div class="card glass table-card">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th><input type="checkbox" id="select-all" onchange="toggleSelectAll()"></th>
                <th>Name</th>
                <th>Type</th>
                <th>Usage</th>
                <th>Conn</th>
                <th>Expiry</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="empty" id="lempty" style="display:none">No inbounds found</div>
      </div>
    </section>

    <section class="page" id="page-addresses">
      <div class="card glass">
        <div class="card-head">
          <div>
            <div class="card-title">Clean IP</div>
            <div class="card-sub">Manage clean IPs and domains</div>
          </div>
        </div>
        <div class="fg">
          <label>Add Addresses</label>
          <textarea id="batch-addrs" placeholder="8.8.8.8&#10;example.com"></textarea>
        </div>
        <div class="tools">
          <button class="btn" onclick="addBatchAddrs()">Add All</button>
          <button class="btn2 btn-danger" onclick="deleteAllAddrs()">Delete All</button>
          <button class="btn2" onclick="bulkDeleteAddrs()">Delete Selected</button>
        </div>
        <div id="addr-list"></div>
      </div>
    </section>

    <section class="page" id="page-ipscanner">
      <div class="card glass">
        <div class="card-head">
          <div>
            <div class="card-title">IP Scanner</div>
            <div class="card-sub">Scan IPs, domains and CIDRs on port 443</div>
          </div>
        </div>
        <div class="fg"><label>Provider</label><div id="provider-btns" class="chips"></div></div>
        <div class="fg" id="range-section" style="display:none"><label>Ranges</label><div id="range-btns" class="chips"></div></div>
        <div class="fg"><label>Targets</label><textarea id="scan-ips" placeholder="8.8.8.8&#10;example.com&#10;1.1.1.0/24"></textarea></div>
        <div class="tools">
          <button class="btn" id="scan-start-btn" onclick="startIPScan()">Scan</button>
          <button class="btn2 btn-danger" id="scan-stop-btn" onclick="stopScan()" style="display:none">Stop</button>
        </div>
        <div class="progress" style="width:100%;height:10px"><span id="scan-progress" style="width:0;background:linear-gradient(90deg,var(--primary),var(--primary2))"></span></div>
        <div style="margin-top:8px;color:var(--muted);font-size:.9rem" id="progress-text">0%</div>
        <div class="table-wrap" style="margin-top:14px">
          <table>
            <thead><tr><th>Address</th><th>Status</th><th>Latency</th></tr></thead>
            <tbody id="scan-tbody"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="page" id="page-logs">
      <div class="card glass">
        <div class="tools">
          <input class="search" id="log-search" placeholder="Search logs..." oninput="filterLogs()">
          <button class="btn2" onclick="fetchLogSize()">Log Size</button>
          <button class="btn2 btn-danger" onclick="clearLogs()">Clear Logs</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Time</th><th>Type</th><th>Event</th></tr></thead>
            <tbody id="logs-tbody"></tbody>
          </table>
        </div>
        <div class="empty" id="logs-empty" style="display:none">No logs</div>
      </div>
    </section>

    <section class="page" id="page-telegram">
      <div class="card glass">
        <div class="card-head">
          <div>
            <div class="card-title">Telegram</div>
            <div class="card-sub">Bot notifications and reports</div>
          </div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Bot Token</label><input id="tg-token"></div>
          <div class="fg"><label>Chat ID</label><input id="tg-chat-id"></div>
        </div>
        <div class="fg"><label>Interval (hours)</label><input id="tg-interval" type="number" min="0.5" step="0.5" value="1"></div>
        <div class="fg"><label>Templates EN</label><textarea id="tg-templates-en"></textarea></div>
        <div class="fg"><label>Templates FA</label><textarea id="tg-templates-fa"></textarea></div>
        <div class="tools">
          <button class="btn" onclick="saveTelegramSettings()">Save</button>
          <button class="btn2" onclick="testTelegram()">Test</button>
          <button class="btn2" onclick="previewTemplate()">Preview</button>
        </div>
        <div class="card glass" id="tg-preview" style="padding:14px"></div>
      </div>
    </section>

    <section class="page" id="page-settings">
      <div class="card glass">
        <div class="card-head">
          <div>
            <div class="card-title">Settings</div>
            <div class="card-sub">General panel configuration</div>
          </div>
        </div>

        <div class="form-grid">
          <div class="fg"><label>Login Text</label><input id="set-footer"></div>
          <div class="fg"><label>Default Path</label><input id="set-default-path" placeholder="/ws/{uid}"></div>
          <div class="fg"><label>Default Traffic Limit (GB)</label><input id="set-default-limit" type="number"></div>
          <div class="fg"><label>Default Expiry (Days)</label><input id="set-default-expiry" type="number"></div>
          <div class="fg"><label>Default Max Connections</label><input id="set-default-maxconn" type="number"></div>
          <div class="fg"><label>Scanner Timeout</label><input id="set-scanner-timeout" type="number"></div>
          <div class="fg"><label>Monthly Limit (GB)</label><input id="set-monthly-limit" type="number"></div>
          <div class="fg"><label>Max Scan IPs</label><input id="set-max-scan-ips" type="number"></div>
          <div class="fg"><label>Keep Alive Interval</label><input id="set-keep-alive-interval" type="number"></div>
          <div class="fg"><label>Theme</label><input id="set-theme-color" value="dark"></div>
        </div>

        <div class="tools">
          <button class="btn" onclick="saveGeneralSettings()">Save All Settings</button>
          <button class="btn2 btn-danger" onclick="resetAllSettings()">Reset Defaults</button>
        </div>

        <hr style="border:0;border-top:1px solid var(--line);margin:18px 0">

        <div class="form-grid">
          <div class="fg"><label>Current Password</label><input type="password" id="cpw"></div>
          <div class="fg"><label>New Password</label><input type="password" id="npw"></div>
        </div>
        <button class="btn2" onclick="chgPw()">Update Password</button>
      </div>
    </section>

    <div class="footer glass">
      <span id="footer-dedication">Best Panel</span>
      <a href="https://t.me/SulgX" target="_blank">Telegram</a>
      <a href="https://github.com/SulgX" target="_blank">GitHub</a>
    </div>
  </main>

  <div class="mobile-bar glass">
    <button class="mobile-item active" data-page="dashboard" onclick="switchPage('dashboard')">Home</button>
    <button class="mobile-item" data-page="inbounds" onclick="switchPage('inbounds')">Inbound</button>
    <button class="mobile-item" data-page="addresses" onclick="switchPage('addresses')">IP</button>
    <button class="mobile-item" data-page="ipscanner" onclick="switchPage('ipscanner')">Scan</button>
    <button class="mobile-item" data-page="logs" onclick="switchPage('logs')">Logs</button>
    <button class="mobile-item" data-page="telegram" onclick="switchPage('telegram')">Bot</button>
    <button class="mobile-item" data-page="settings" onclick="switchPage('settings')">Settings</button>
  </div>
</div>

<div class="modal" id="mo-add">
  <div class="modal-box glass">
    <div class="modal-head">
      <div class="modal-title">Create Inbound</div>
      <button class="close" onclick="closeModal('mo-add')">✕</button>
    </div>
    <div class="form-grid">
      <div class="fg"><label>Name</label><input id="nl" placeholder="This Server is Free"></div>
      <div class="fg"><label>UUID</label><input id="auuid" placeholder="Auto generate if empty"></div>
      <div class="fg"><label>Traffic Limit (GB)</label><input id="nv" type="number" value="0"></div>
      <div class="fg"><label>Max Connections</label><input id="nc" type="number" value="0"></div>
      <div class="fg"><label>Validity (Days)</label><input id="nd" type="number" value="0"></div>
      <div class="fg"><label>Color</label><input id="alink-color" type="color" value="#6ee7ff"></div>
      <div class="fg"><label>Path</label><input id="ap" placeholder="/ws/{uid}"></div>
      <div class="fg"><label>SNI</label><input id="asni"></div>
      <div class="fg"><label>Host</label><input id="ahost"></div>
      <div class="fg"><label>Fingerprint</label><input id="afp" value="chrome"></div>
      <div class="fg"><label>Flag</label><input id="flag-code-create" maxlength="2" placeholder="us"></div>
      <div class="fg"><label>Fragment</label><input id="afrag"></div>
    </div>
    <div class="tools">
      <button class="btn" onclick="createLink()">Create</button>
      <button class="btn2" onclick="generateUUID('auuid')">Generate UUID</button>
    </div>
  </div>
</div>

<div class="modal" id="mo-edit">
  <div class="modal-box glass">
    <div class="modal-head">
      <div class="modal-title" id="et">Edit Inbound</div>
      <button class="close" onclick="closeModal('mo-edit')">✕</button>
    </div>
    <input type="hidden" id="eu">
    <div class="form-grid">
      <div class="fg"><label>UUID</label><input id="euuid" readonly></div>
      <div class="fg"><label>Name</label><input id="en2"></div>
      <div class="fg"><label>Traffic Limit (GB)</label><input id="el" type="number"></div>
      <div class="fg"><label>Max Connections</label><input id="ec" type="number"></div>
      <div class="fg"><label>Validity (Days)</label><input id="ed" type="number"></div>
      <div class="fg"><label>Color</label><input id="e-color" type="color" value="#6ee7ff"></div>
      <div class="fg"><label>Path</label><input id="ep"></div>
      <div class="fg"><label>SNI</label><input id="esni"></div>
      <div class="fg"><label>Host</label><input id="ehost"></div>
      <div class="fg"><label>Fingerprint</label><input id="efp"></div>
      <div class="fg"><label>Flag</label><input id="flag-code-edit" maxlength="2"></div>
      <div class="fg"><label>Fragment</label><input id="efrag"></div>
    </div>
    <div class="tools">
      <button class="btn" onclick="saveEdit()">Save</button>
      <button class="btn2" onclick="resetTraf()">Reset Usage</button>
    </div>
  </div>
</div>

<div class="modal" id="mo-qr">
  <div class="modal-box glass" style="width:min(380px,92vw)">
    <div class="modal-head">
      <div class="modal-title">QR Code</div>
      <button class="close" onclick="closeModal('mo-qr')">✕</button>
    </div>
    <div class="qrbox"><img id="qr-img" src=""></div>
  </div>
</div>

<div class="modal" id="mo-addr-edit">
  <div class="modal-box glass" style="width:min(460px,92vw)">
    <div class="modal-head">
      <div class="modal-title">Edit Address</div>
      <button class="close" onclick="closeModal('mo-addr-edit')">✕</button>
    </div>
    <div class="fg"><label>New Address</label><input id="edit-addr-input"></div>
    <button class="btn" onclick="saveAddrEdit()">Save</button>
  </div>
</div>

<script>
const $=s=>document.querySelector(s),$m=id=>document.getElementById(id);
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}

let lang=localStorage.getItem('ll')||'en',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,doughnutChart=null,speedChart=null;
let allAddrs=[],isAuthenticated=false,selectedUids=new Set(),selectedAddrIndices=new Set();
let prevUploadBytes=null,prevDownloadBytes=null,prevStatsTime=null,uploadSpeedAvg=0,downloadSpeedAvg=0;
let timezoneOffset=0,editingAddrIndex=-1,wsScanner=null,totalScanCount=0,scannedCount=0,currentProvider=null,speedHistory=[];

const footerTexts={
  en:'Dedicated to the people of my homeland Iran from <a href="https://github.com/SulgX" target="_blank">SulgX</a>',
  fa:'تقدیم به مردم سرزمینم ایران از طرف <a href="https://github.com/SulgX" target="_blank">SulgX</a>'
};

const i18n={en:{on:'On',off:'Off',success:'Success',failed:'Failed',updatedAt:'Updated {time}'},fa:{on:'روشن',off:'خاموش',success:'موفق',failed:'ناموفق',updatedAt:'بروزرسانی {time}' }};
function t(key,params={}){
  let str=(i18n[lang]&&i18n[lang][key])||key;
  for(const k in params) str=str.replace(`{${k}}`,params[k]);
  return str;
}
function codeToFlag(code){
  if(!code||code.length!==2) return '';
  code=code.toUpperCase();
  return String.fromCodePoint(0x1F1E6+code.charCodeAt(0)-65)+String.fromCodePoint(0x1F1E6+code.charCodeAt(1)-65);
}
function toast(msg,err=false){
  const t=$m('toast'); t.textContent=msg;
  t.style.background=err?'rgba(127,29,29,.92)':'rgba(15,23,42,.92)';
  t.classList.add('show');
  clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),2600);
}
function closeModal(id){$m(id).classList.remove('show')}
function openModal(id){$m(id).classList.add('show')}
function setTheme(t){
  theme=t;
  document.body.classList.toggle('light-mode',t==='light');
  document.body.classList.toggle('blue-mode',t==='blue-dark');
  localStorage.setItem('theme',t);
  updChartColors();
}
function toggleTheme(){
  const arr=['dark','light','blue-dark'];
  const i=arr.indexOf(theme);
  setTheme(arr[(i+1)%arr.length]);
}
function setLang(l){
  lang=l;
  localStorage.setItem('ll',l);
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll('.lang-'+l).forEach(e=>e.classList.add('active'));
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l);
    if(v) el.textContent=v;
  });
  const footer=$m('footer-dedication');
  if(footer) footer.innerHTML=footerTexts[l]||footerTexts.en;
}
async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    if((await r.json()).authenticated) await showDashboard();
    else showLogin();
  }catch{showLogin()}
}
function showLogin(){
  isAuthenticated=false;
  $m('login-page').style.display='';
  $m('dashboard-page').style.display='none';
  fetch('/api/public-settings').then(r=>r.json()).then(d=>{
    if(d.footer_text) $m('login-custom-message').textContent=d.footer_text;
  }).catch(()=>{});
}
async function showDashboard(){
  isAuthenticated=true;
  $m('login-page').style.display='none';
  $m('dashboard-page').style.display='';
  setLang(lang); setTheme(theme);
  bindNav();
  initChart(); initDoughnutChart(); initSpeedChart();
  await loadGeneralSettings();
  await loadStats();
  await loadLinks();
  await loadAddrs();
  await loadLogs();
  await loadLoginLogs();
  await loadTelegramSettings();
  buildProviderPills();
}
function bindNav(){
  document.querySelectorAll('.nav-link').forEach(el=>{
    el.onclick=()=>switchPage(el.dataset.page);
  });
}
function switchPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  $m('page-'+id).classList.add('active');
  document.querySelectorAll('.nav-link').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
  document.querySelectorAll('.mobile-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
}
async function doLogin(){
  const pw=$m('login-pw').value;
  $m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    if(r.ok){$m('login-pw').value=''; await showDashboard();}
    else $m('login-err').style.display='block';
  }catch{$m('login-err').style.display='block'}
}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}

function fmtB(b){
  if(!b||b===0) return '0 B';
  if(b>=1073741824) return (b/1073741824).toFixed(2)+' GB';
  if(b>=1048576) return (b/1048576).toFixed(2)+' MB';
  return (b/1024).toFixed(1)+' KB';
}
function fmtLim(b){ if(!b||b===0) return '∞'; return (b/1073741824).toFixed(1)+' GB'; }
function fmtExp(ea){
  if(!ea) return '∞';
  const d=new Date(ea)-new Date();
  if(d<=0) return 'Expired';
  const days=Math.floor(d/86400000);
  if(days>0) return days+'d';
  const h=Math.floor(d/3600000);
  if(h>0) return h+'h';
  return Math.floor(d/60000)+'m';
}
function safeSetText(id,v){const el=$m(id); if(el) el.textContent=v}
function safeSetHTML(id,v){const el=$m(id); if(el) el.innerHTML=v}
function formatSpeed(bps){
  if(!bps||bps<1) return '0 KB/s';
  if(bps<1024) return bps.toFixed(1)+' B/s';
  const kb=bps/1024;
  if(kb<1024) return kb.toFixed(1)+' KB/s';
  return (kb/1024).toFixed(2)+' MB/s';
}

async function loadStats(){
  try{
    const r=await fetch('/stats');
    if(r.status===401){showLogin();return}
    sData=await r.json();

    safeSetHTML('sv-traffic',(sData.total_traffic_mb||0)+' MB');
    safeSetText('sv-requests',sData.total_requests||0);
    safeSetText('sv-conns',sData.active_connections||0);
    safeSetHTML('sv-disk',(sData.disk_free_gb||0)+' GB');
    safeSetText('sv-uptime',sData.uptime||'--');
    safeSetText('sidebar-uptime',sData.uptime||'--');
    safeSetText('last-up',t('updatedAt',{time:new Date().toLocaleTimeString()}));

    const cpu=sData.cpu_percent??0, mem=sData.memory_percent??0;
    safeSetText('cpu-v',Number(cpu).toFixed(1)+'%');
    safeSetText('mem-v',Number(mem).toFixed(1)+'%');
    $m('cpu-b').style.width=cpu+'%';
    $m('mem-b').style.width=mem+'%';

    const monthlyUsageGB=sData.monthly_usage_bytes?(sData.monthly_usage_bytes/1073741824):0;
    const monthlyLimitGB=sData.monthly_limit_bytes?(sData.monthly_limit_bytes/1073741824):0;
    safeSetText('sv-monthly',monthlyLimitGB>0?`${monthlyUsageGB.toFixed(1)} / ${monthlyLimitGB.toFixed(1)} GB`:`${monthlyUsageGB.toFixed(1)} GB`);

    const now=Date.now();
    if(prevUploadBytes===null){
      prevUploadBytes=sData.upload_bytes||0;
      prevDownloadBytes=sData.download_bytes||0;
      prevStatsTime=now;
      safeSetText('sv-up-speed','0 KB/s');
      safeSetText('sv-down-speed','0 KB/s');
            safeSetText('sv-down-speed','0 KB/s');
    } else {
      const dt = Math.max((now - prevStatsTime) / 1000, 1);
      const up = Math.max(((sData.upload_bytes || 0) - prevUploadBytes) / dt, 0);
      const down = Math.max(((sData.download_bytes || 0) - prevDownloadBytes) / dt, 0);

      uploadSpeedAvg = uploadSpeedAvg ? uploadSpeedAvg * 0.65 + up * 0.35 : up;
      downloadSpeedAvg = downloadSpeedAvg ? downloadSpeedAvg * 0.65 + down * 0.35 : down;

      safeSetText('sv-up-speed', formatSpeed(uploadSpeedAvg));
      safeSetText('sv-down-speed', formatSpeed(downloadSpeedAvg));

      prevUploadBytes = sData.upload_bytes || 0;
      prevDownloadBytes = sData.download_bytes || 0;
      prevStatsTime = now;

      updateSpeedChart(uploadSpeedAvg, downloadSpeedAvg);
    }

    if (tChart && Array.isArray(sData.hourly_traffic)) {
      tChart.data.labels = sData.hourly_traffic.map(x => x.hour || '');
      tChart.data.datasets[0].data = sData.hourly_traffic.map(x => x.mb || 0);
      tChart.update();
    }
  } catch (e) {
    console.warn(e);
  }
}

function chartTextColor() {
  return getComputedStyle(document.body).getPropertyValue('--muted').trim() || '#9cb4cf';
}

function updChartColors() {
  const color = chartTextColor();
  [tChart, doughnutChart, speedChart].forEach(ch => {
    if (!ch) return;
    if (ch.options.scales) {
      Object.values(ch.options.scales).forEach(s => {
        if (s.ticks) s.ticks.color = color;
        if (s.grid) s.grid.color = 'rgba(255,255,255,.08)';
      });
    }
    if (ch.options.plugins?.legend?.labels) ch.options.plugins.legend.labels.color = color;
    ch.update();
  });
}

function initChart() {
  const ctx = $m('tc');
  if (!ctx || tChart) return;
  tChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Traffic MB',
        data: [],
        borderColor: '#6ee7ff',
        backgroundColor: 'rgba(110,231,255,.14)',
        tension: .42,
        fill: true,
        pointRadius: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: chartTextColor() } } },
      scales: {
        x: { ticks: { color: chartTextColor() }, grid: { color: 'rgba(255,255,255,.06)' } },
        y: { ticks: { color: chartTextColor() }, grid: { color: 'rgba(255,255,255,.06)' } }
      }
    }
  });
}

function initDoughnutChart() {
  const ctx = $m('doughnut-chart');
  if (!ctx || doughnutChart) return;
  doughnutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Used', 'Free'],
      datasets: [{
        data: [1, 1],
        backgroundColor: ['#6ee7ff', 'rgba(255,255,255,.12)'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: { legend: { labels: { color: chartTextColor() } } }
    }
  });
}

function initSpeedChart() {
  const ctx = $m('speed-chart');
  if (!ctx || speedChart) return;
  speedChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Download',
          data: [],
          borderColor: '#4ade80',
          backgroundColor: 'rgba(74,222,128,.12)',
          tension: .35,
          fill: true,
          pointRadius: 0
        },
        {
          label: 'Upload',
          data: [],
          borderColor: '#fbbf24',
          backgroundColor: 'rgba(251,191,36,.10)',
          tension: .35,
          fill: true,
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { labels: { color: chartTextColor() } } },
      scales: {
        x: { ticks: { color: chartTextColor() }, grid: { color: 'rgba(255,255,255,.06)' } },
        y: { ticks: { color: chartTextColor() }, grid: { color: 'rgba(255,255,255,.06)' } }
      }
    }
  });
}

function updateSpeedChart(up, down) {
  if (!speedChart) return;
  const label = new Date().toLocaleTimeString();
  speedChart.data.labels.push(label);
  speedChart.data.datasets[0].data.push(Math.round(down / 1024));
  speedChart.data.datasets[1].data.push(Math.round(up / 1024));

  if (speedChart.data.labels.length > 20) {
    speedChart.data.labels.shift();
    speedChart.data.datasets[0].data.shift();
    speedChart.data.datasets[1].data.shift();
  }
  speedChart.update();
}

async function loadLinks() {
  try {
    const r = await fetch('/api/links');
    if (r.status === 401) return showLogin();
    allLinks = await r.json();
    renderLinks();
    updateUsageChart();
  } catch (e) {
    console.warn(e);
  }
}

function updateUsageChart() {
  if (!doughnutChart) return;
  const used = allLinks.reduce((a, x) => a + (x.used_bytes || x.usage_bytes || 0), 0);
  const limit = allLinks.reduce((a, x) => a + (x.limit_bytes || 0), 0);
  const free = limit > 0 ? Math.max(limit - used, 0) : used || 1;
  doughnutChart.data.datasets[0].data = [used || 1, free || 1];
  doughnutChart.update();
}

function filteredLinks() {
  const q = ($m('srch')?.value || '').toLowerCase().trim();
  return allLinks.filter(x => {
    const active = x.enabled !== false && x.active !== false;
    if (cf === 'active' && !active) return false;
    if (cf === 'off' && active) return false;
    if (!q) return true;
    return JSON.stringify(x).toLowerCase().includes(q);
  });
}

function renderLinks() {
  const tb = $m('ltb');
  if (!tb) return;
  const rows = filteredLinks();
  $m('lempty').style.display = rows.length ? 'none' : '';

  tb.innerHTML = rows.map(x => {
    const uid = x.uid || x.uuid || x.id || '';
    const name = x.name || x.label || 'Unnamed';
    const active = x.enabled !== false && x.active !== false;
    const used = x.used_bytes || x.usage_bytes || 0;
    const lim = x.limit_bytes || x.traffic_limit || 0;
    const pct = lim ? Math.min(100, Math.round(used / lim * 100)) : 0;
    const flag = codeToFlag(x.flag || x.flag_code || '');

    return `
      <tr>
        <td><input type="checkbox" class="row-check" data-uid="${esc(uid)}" ${selectedUids.has(uid) ? 'checked' : ''} onchange="toggleRow('${esc(uid)}',this.checked)"></td>
        <td><b>${flag} ${esc(name)}</b><div class="k">${esc(uid)}</div></td>
        <td><span class="badge type">${esc(x.type || x.protocol || 'VLESS')}</span></td>
        <td>
          <b>${fmtB(used)}</b> / ${fmtLim(lim)}
          <div class="progress"><span style="width:${pct}%;background:linear-gradient(90deg,var(--primary),var(--primary2))"></span></div>
        </td>
        <td>${x.current_connections || x.connections || 0}</td>
        <td>${fmtExp(x.expires_at || x.expiry || x.expire_at)}</td>
        <td><span class="badge ${active ? 'on' : 'off'}">${active ? t('on') : t('off')}</span></td>
        <td>
          <div class="actions">
            <button class="a-btn" onclick="copyLink('${esc(uid)}')">Copy</button>
            <button class="a-btn" onclick="showQR('${esc(uid)}')">QR</button>
            <button class="a-btn warn" onclick="showEdit('${esc(uid)}')">Edit</button>
            <button class="a-btn ${active ? 'danger' : 'ok'}" onclick="toggleLink('${esc(uid)}')">${active ? 'Off' : 'On'}</button>
            <button class="a-btn danger" onclick="delLink('${esc(uid)}')">Del</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function filterLinks() { renderLinks(); }

function setFilter(f, el) {
  cf = f;
  document.querySelectorAll('.chip').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  renderLinks();
}

function toggleRow(uid, checked) {
  checked ? selectedUids.add(uid) : selectedUids.delete(uid);
}

function toggleSelectAll() {
  const checked = $m('select-all').checked;
  filteredLinks().forEach(x => {
    const uid = x.uid || x.uuid || x.id || '';
    checked ? selectedUids.add(uid) : selectedUids.delete(uid);
  });
  renderLinks();
}

function showAddMo() {
  openModal('mo-add');
}

async function generateUUID(target) {
  try {
    const r = await fetch('/api/generate-uuid');
    const d = await r.json();
    $m(target).value = d.uuid || d.id || crypto.randomUUID();
  } catch {
    $m(target).value = crypto.randomUUID();
  }
}

async function createLink() {
  const payload = {
    name: $m('nl').value.trim(),
    uuid: $m('auuid').value.trim(),
    limit_gb: Number($m('nv').value || 0),
    max_connections: Number($m('nc').value || 0),
    days: Number($m('nd').value || 0),
    color: $m('alink-color').value,
    path: $m('ap').value.trim(),
    sni: $m('asni').value.trim(),
    host: $m('ahost').value.trim(),
    fp: $m('afp').value.trim(),
    flag: $m('flag-code-create').value.trim(),
    fragment: $m('afrag').value.trim()
  };

  if (!payload.name) return toast('Name is required', true);

  try {
    const r = await fetch('/api/links', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!r.ok) throw 0;
    closeModal('mo-add');
    toast('Inbound created');
    await loadLinks();
  } catch {
    toast('Create failed', true);
  }
}

function findLink(uid) {
  return allLinks.find(x => String(x.uid || x.uuid || x.id) === String(uid));
}

function showEdit(uid) {
  const x = findLink(uid);
  if (!x) return;

  $m('eu').value = uid;
  $m('euuid').value = x.uuid || x.uid || x.id || '';
  $m('en2').value = x.name || x.label || '';
  $m('el').value = x.limit_gb || (x.limit_bytes ? (x.limit_bytes / 1073741824).toFixed(2) : 0);
  $m('ec').value = x.max_connections || 0;
  $m('ed').value = x.days || 0;
  $m('e-color').value = x.color || '#6ee7ff';
  $m('ep').value = x.path || '';
  $m('esni').value = x.sni || '';
  $m('ehost').value = x.host || '';
  $m('efp').value = x.fp || x.fingerprint || 'chrome';
  $m('flag-code-edit').value = x.flag || x.flag_code || '';
  $m('efrag').value = x.fragment || '';
  openModal('mo-edit');
}

async function saveEdit() {
  const uid = $m('eu').value;
  const payload = {
    name: $m('en2').value.trim(),
    limit_gb: Number($m('el').value || 0),
    max_connections: Number($m('ec').value || 0),
    days: Number($m('ed').value || 0),
    color: $m('e-color').value,
    path: $m('ep').value.trim(),
    sni: $m('esni').value.trim(),
    host: $m('ehost').value.trim(),
    fp: $m('efp').value.trim(),
    flag: $m('flag-code-edit').value.trim(),
    fragment: $m('efrag').value.trim()
  };

  try {
    const r = await fetch('/api/links/' + encodeURIComponent(uid), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!r.ok) throw 0;
    closeModal('mo-edit');
    toast('Saved');
    await loadLinks();
  } catch {
    toast('Save failed', true);
  }
}

async function toggleLink(uid) {
  try {
    await fetch('/api/links/' + encodeURIComponent(uid) + '/toggle', { method: 'POST' });
    await loadLinks();
  } catch {
    toast('Toggle failed', true);
  }
}

async function delLink(uid) {
  if (!confirm('Delete this inbound?')) return;
  try {
    await fetch('/api/links/' + encodeURIComponent(uid), { method: 'DELETE' });
    selectedUids.delete(uid);
    toast('Deleted');
    await loadLinks();
  } catch {
    toast('Delete failed', true);
  }
}

async function resetTraf() {
  const uid = $m('eu').value;
  try {
    await fetch('/api/links/' + encodeURIComponent(uid) + '/reset-usage', { method: 'POST' });
    toast('Usage reset');
    await loadLinks();
  } catch {
    toast('Reset failed', true);
  }
}

async function copyLink(uid) {
  try {
    const r = await fetch('/api/links/' + encodeURIComponent(uid) + '/config');
    const d = await r.json();
    const text = d.link || d.config || d.url || '';
    await navigator.clipboard.writeText(text);
    toast('Copied');
  } catch {
    toast('Copy failed', true);
  }
}

function showQR(uid) {
  $m('qr-img').src = '/api/links/' + encodeURIComponent(uid) + '/qr?t=' + Date.now();
  openModal('mo-qr');
}

async function batchAction(action) {
  const ids = [...selectedUids];
  if (!ids.length) return toast('Select at least one inbound', true);
  if (action === 'delete' && !confirm('Delete selected inbounds?')) return;

  try {
    const r = await fetch('/api/links/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, ids })
    });
    if (!r.ok) throw 0;
    selectedUids.clear();
    toast('Batch action done');
    await loadLinks();
  } catch {
    toast('Batch action failed', true);
  }
}

function exportLinks() {
  const blob = new Blob([JSON.stringify(allLinks, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'best-panel-inbounds.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function importLinks(input) {
  const file = input.files?.[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    const r = await fetch('/api/links/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ links: data })
    });
    if (!r.ok) throw 0;
    toast('Imported');
    await loadLinks();
  } catch {
    toast('Import failed', true);
  } finally {
    input.value = '';
  }
}

async function randomInbound() {
  try {
    const r = await fetch('/api/links/random', { method: 'POST' });
    if (!r.ok) throw 0;
    toast('Random inbound created');
    await loadLinks();
  } catch {
    showAddMo();
    generateUUID('auuid');
  }
}

async function loadAddrs() {
  try {
    const r = await fetch('/api/addresses');
    allAddrs = await r.json();
    renderAddrs();
  } catch {
    allAddrs = [];
    renderAddrs();
  }
}

function renderAddrs() {
  const box = $m('addr-list');
  if (!box) return;
  if (!allAddrs.length) {
    box.innerHTML = '<div class="empty">No addresses</div>';
    return;
  }

  box.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr><th></th><th>Address</th><th>Actions</th></tr></thead>
        <tbody>
          ${allAddrs.map((a, i) => `
            <tr>
              <td><input type="checkbox" ${selectedAddrIndices.has(i) ? 'checked' : ''} onchange="this.checked?selectedAddrIndices.add(${i}):selectedAddrIndices.delete(${i})"></td>
              <td>${esc(a.address || a)}</td>
              <td>
                <button class="a-btn warn" onclick="editAddr(${i})">Edit</button>
                <button class="a-btn danger" onclick="deleteAddr(${i})">Delete</button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

async function addBatchAddrs() {
  const val = $m('batch-addrs').value.trim();
  if (!val) return;
  const addresses = val.split(/
+/).map(x => x.trim()).filter(Boolean);
  try {
    await fetch('/api/addresses/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ addresses })
    });
    $m('batch-addrs').value = '';
    toast('Addresses added');
    await loadAddrs();
  } catch {
    toast('Add failed', true);
  }
}

function editAddr(i) {
  editingAddrIndex = i;
  const a = allAddrs[i];
  $m('edit-addr-input').value = a.address || a;
  openModal('mo-addr-edit');
}

async function saveAddrEdit() {
  const address = $m('edit-addr-input').value.trim();
  if (!address) return;
  try {
    await fetch('/api/addresses/' + editingAddrIndex, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address })
    });
    closeModal('mo-addr-edit');
    toast('Address updated');
    await loadAddrs();
  } catch {
    toast('Update failed', true);
  }
}

async function deleteAddr(i) {
  if (!confirm('Delete address?')) return;
  try {
    await fetch('/api/addresses/' + i, { method: 'DELETE' });
    selectedAddrIndices.delete(i);
    await loadAddrs();
  } catch {
    toast('Delete failed', true);
  }
}

async function bulkDeleteAddrs() {
  const ids = [...selectedAddrIndices];
  if (!ids.length) return toast('Select addresses', true);
  try {
    await fetch('/api/addresses/batch-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indices: ids })
    });
    selectedAddrIndices.clear();
    await loadAddrs();
  } catch {
    toast('Delete failed', true);
  }
}

async function deleteAllAddrs() {
  if (!confirm('Delete all addresses?')) return;
  try {
    await fetch('/api/addresses', { method: 'DELETE' });
    selectedAddrIndices.clear();
    await loadAddrs();
  } catch {
    toast('Delete failed', true);
  }
}

async function loadLogs() {
  try {
    const r = await fetch('/api/logs');
    const logs = await r.json();
    renderLogs(logs);
  } catch {
    renderLogs([]);
  }
}

function renderLogs(logs) {
  const tb = $m('logs-tbody');
  if (!tb) return;
  window.__logs = logs || [];
  filterLogs();
}

function filterLogs() {
  const q = ($m('log-search')?.value || '').toLowerCase();
  const logs = window.__logs || [];
  const filtered = logs.filter(x => JSON.stringify(x).toLowerCase().includes(q));
  $m('logs-empty').style.display = filtered.length ? 'none' : '';

  $m('logs-tbody').innerHTML = filtered.map((x, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${esc(x.time || x.created_at || '')}</td>
      <td><span class="badge type">${esc(x.type || x.level || 'info')}</span></td>
      <td>${esc(x.event || x.message || JSON.stringify(x))}</td>
    </tr>
  `).join('');
}

async function clearLogs() {
  if (!confirm('Clear logs?')) return;
  try {
    await fetch('/api/logs', { method: 'DELETE' });
    await loadLogs();
  } catch {
    toast('Clear failed', true);
  }
}

async function fetchLogSize() {
  try {
    const r = await fetch('/api/logs/size');
    const d = await r.json();
    toast('Log size: ' + (d.size || d.size_human || 'unknown'));
  } catch {
    toast('Could not fetch log size', true);
  }
}

async function loadLoginLogs() {
  try {
    const r = await fetch('/api/login-logs');
    const logs = await r.json();
    const tb = $m('login-logs-tbody');
    if (!tb) return;
    tb.innerHTML = (logs || []).slice(0, 8).map(x => `
      <tr>
        <td>${esc(x.time || x.created_at || '')}</td>
        <td>${esc(x.ip || '')}<div class="k">${esc(x.agent || x.user_agent || '')}</div></td>
        <td><span class="badge ${x.success === false ? 'off' : 'on'}">${x.success === false ? t('failed') : t('success')}</span></td>
      </tr>
    `).join('');
  } catch {}
}

async function loadTelegramSettings() {
  try {
    const r = await fetch('/api/telegram/settings');
    const d = await r.json();
    $m('tg-token').value = d.token || '';
    $m('tg-chat-id').value = d.chat_id || '';
    $m('tg-interval').value = d.interval_hours || 1;
    $m('tg-templates-en').value = d.templates_en || '';
    $m('tg-templates-fa').value = d.templates_fa || '';
  } catch {}
}

async function saveTelegramSettings() {
  const payload = {
    token: $m('tg-token').value.trim(),
    chat_id: $m('tg-chat-id').value.trim(),
    interval_hours: Number($m('tg-interval').value || 1),
    templates_en: $m('tg-templates-en').value,
    templates_fa: $m('tg-templates-fa').value
  };
  try {
    await fetch('/api/telegram/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    toast('Telegram settings saved');
  } catch {
    toast('Save failed', true);
  }
}

async function testTelegram() {
  try {
    const r = await fetch('/api/telegram/test', { method: 'POST' });
    if (!r.ok) throw 0;
    toast('Test sent');
  } catch {
    toast('Telegram test failed', true);
  }
}

function previewTemplate() {
  const txt = lang === 'fa' ? $m('tg-templates-fa').value : $m('tg-templates-en').value;
  $m('tg-preview').textContent = txt || 'No template';
}

async function loadGeneralSettings() {
  try {
    const r = await fetch('/api/settings');
    const d = await r.json();

    $m('set-footer').value = d.footer_text || '';
    $m('set-default-path').value = d.default_path || '/ws/{uid}';
    $m('set-default-limit').value = d.default_limit_gb ?? 0;
    $m('set-default-expiry').value = d.default_expiry_days ?? 0;
    $m('set-default-maxconn').value = d.default_max_connections ?? 0;
    $m('set-scanner-timeout').value = d.scanner_timeout ?? 3;
    $m('set-monthly-limit').value = d.monthly_limit_gb ?? 0;
    $m('set-max-scan-ips').value = d.max_scan_ips ?? 256;
    $m('set-keep-alive-interval').value = d.keep_alive_interval ?? 30;
    $m('set-theme-color').value = d.theme_color || theme;
  } catch {}
}

async function saveGeneralSettings() {
  const payload = {
    footer_text: $m('set-footer').value,
    default_path: $m('set-default-path').value,
    default_limit_gb: Number($m('set-default-limit').value || 0),
    default_expiry_days: Number($m('set-default-expiry').value || 0),
    default_max_connections: Number($m('set-default-maxconn').value || 0),
    scanner_timeout: Number($m('set-scanner-timeout').value || 3),
    monthly_limit_gb: Number($m('set-monthly-limit').value || 0),
    max_scan_ips: Number($m('set-max-scan-ips').value || 256),
    keep_alive_interval: Number($m('set-keep-alive-interval').value || 30),
    theme_color: $m('set-theme-color').value || theme
  };

  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    toast('Settings saved');
  } catch {
    toast('Save failed', true);
  }
}

async function resetAllSettings() {
  if (!confirm('Reset settings?')) return;
  try {
    await fetch('/api/settings/reset', { method: 'POST' });
    toast('Settings reset');
    await loadGeneralSettings();
  } catch {
    toast('Reset failed', true);
  }
}

async function chgPw() {
  const current_password = $m('cpw').value;
  const new_password = $m('npw').value;
  if (!current_password || !new_password) return toast('Fill both passwords', true);

  try {
    const r = await fetch('/api/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password, new_password })
    });
    if (!r.ok) throw 0;
    $m('cpw').value = '';
    $m('npw').value = '';
    toast('Password updated');
  } catch {
    toast('Password update failed', true);
  }
}

const providers = {
  cloudflare: ['104.16.0.0/12', '172.64.0.0/13', '188.114.96.0/20'],
  google: ['8.8.8.8', '8.8.4.4'],
  quad9: ['9.9.9.9', '149.112.112.112'],
  custom: []
};

function buildProviderPills() {
  const pbox = $m('provider-btns');
  if (!pbox) return;
  pbox.innerHTML = Object.keys(providers).map(p => `<button class="chip" onclick="pickProvider('${p}',this)">${p}</button>`).join('');
}

function pickProvider(p, el) {
  currentProvider = p;
  document.querySelectorAll('#provider-btns .chip').forEach(x => x.classList.remove('active'));
  el.classList.add('active');

  const ranges = providers[p] || [];
  $m('range-section').style.display = ranges.length ? '' : 'none';
  $m('range-btns').innerHTML = ranges.map(r => `<button class="chip" onclick="addScanTarget('${r}')">${r}</button>`).join('');
}

function addScanTarget(v) {
  const ta = $m('scan-ips');
  ta.value = (ta.value.trim() ? ta.value.trim() + '
' : '') + v;
}

function startIPScan() {
  const targets = $m('scan-ips').value.trim();
  if (!targets) return toast('Enter targets', true);

  $m('scan-tbody').innerHTML = '';
  $m('scan-progress').style.width = '0%';
  $m('progress-text').textContent = '0%';
  $m('scan-start-btn').style.display = 'none';
  $m('scan-stop-btn').style.display = '';

  try {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    wsScanner = new WebSocket(`${proto}//${location.host}/ws/ipscan`);
    wsScanner.onopen = () => wsScanner.send(JSON.stringify({ targets }));
    wsScanner.onmessage = ev => {
      const d = JSON.parse(ev.data);
      if (d.total) totalScanCount = d.total;
      if (d.result) {
        scannedCount++;
        const ok = d.result.open || d.result.status === 'open';
        $m('scan-tbody').insertAdjacentHTML('beforeend', `
          <tr>
            <td>${esc(d.result.address || d.result.ip || '')}</td>
            <td><span class="badge ${ok ? 'on' : 'off'}">${ok ? 'Open' : 'Closed'}</span></td>
            <td>${esc(d.result.latency || d.result.ping || '-')}</td>
          </tr>
        `);
      }
      if (d.progress !== undefined || totalScanCount) {
        const pct = d.progress ?? Math.round(scannedCount / Math.max(totalScanCount, 1) * 100);
        $m('scan-progress').style.width = pct + '%';
        $m('progress-text').textContent = pct + '%';
      }
      if (d.done) finishScan();
    };
    wsScanner.onerror = () => {
      toast('Scanner error', true);
      finishScan();
    };
    wsScanner.onclose = () => finishScan();
  } catch {
    toast('Scanner failed', true);
    finishScan();
  }
}

function stopScan() {
  try {
    wsScanner?.close();
  } catch {}
  finishScan();
}

function finishScan() {
  $m('scan-start-btn').style.display = '';
  $m('scan-stop-btn').style.display = 'none';
}

setInterval(() => {
  if (isAuthenticated) {
    loadStats();
  }
}, 5000);

setInterval(() => {
  if (isAuthenticated) {
    loadLinks();
  }
}, 15000);

document.addEventListener('DOMContentLoaded', () => {
  setLang(lang);
  setTheme(theme);
  checkAuth();
});
</script>
</body>
</html>'''

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    return HTMLResponse(content=PANEL_HTML)

if __name__ == "__main__":
    import sys
    import subprocess
    import os
    port = int(os.environ.get("PORT", CONFIG.get("port", 8000)))
    logger.info(f"Starting Best Panel on port {port}")
    try:
        subprocess.run(
            [
                sys.executable, "-m", "uvicorn",
                "main:app",
                "--host", "0.0.0.0", 
                "--port", str(port),  
                "--proxy-headers",
                "--forwarded-allow-ips", "*"
            ],
            check=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
