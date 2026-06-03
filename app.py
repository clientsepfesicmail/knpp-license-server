import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import tempfile
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from flask import Flask, jsonify, redirect, request, send_from_directory
from supabase import Client, create_client
from werkzeug.utils import secure_filename

from web_statement_processor import count_pdf_pages, process_bank_statement, processor_capabilities

try:
    import boto3
    from botocore.client import Config as BotoConfig
except Exception:  # Storage remains disabled until boto3 is installed/configured.
    boto3 = None
    BotoConfig = None

app = Flask(__name__, static_folder="admin", static_url_path="")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "knpp@admin2024")
SERVER_SECRET = os.environ.get("SERVER_SECRET", "knpp_secret_key_change_this")
ADMIN_EMAILS = {email.strip().lower() for email in os.environ.get("ADMIN_EMAILS", "capinkupatowary@gmail.com,prodip252@gmail.com").split(",") if email.strip()}
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "24"))
BRAND_NAME = "Tezhisab"
LICENSE_PREFIX = "PPPM"
DEFAULT_PRODUCT_CODE = "EEM"

# Cloudflare R2 central file storage. Keep all credentials in Render Environment Variables.
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID", "").strip()
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME", "").strip()
R2_ENDPOINT_URL = os.environ.get("R2_ENDPOINT_URL", "").strip() or (f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com" if R2_ACCOUNT_ID else "")
R2_SIGNED_URL_SECONDS = int(os.environ.get("R2_SIGNED_URL_SECONDS", "3600"))
R2_UPLOAD_URL_SECONDS = int(os.environ.get("R2_UPLOAD_URL_SECONDS", "3600"))
MAX_APP_UPLOAD_MB = int(os.environ.get("MAX_APP_UPLOAD_MB", "500"))
APP_VERSION_RETENTION_COUNT = max(1, int(os.environ.get("APP_VERSION_RETENTION_COUNT", "2")))
AUTO_DELETE_OLDER_VERSIONS = os.environ.get("AUTO_DELETE_OLDER_VERSIONS", "true").strip().lower() not in {"0", "false", "no", "off"}
ALLOWED_APP_EXTENSIONS = {".exe", ".apk", ".msi", ".zip"}
ALLOWED_REQUIREMENT_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".zip"}
MAX_REQUIREMENT_UPLOAD_MB = int(os.environ.get("MAX_REQUIREMENT_UPLOAD_MB", "15"))
MAX_RECHARGE_SCREENSHOT_MB = int(os.environ.get("MAX_RECHARGE_SCREENSHOT_MB", "5"))
ALLOWED_RECHARGE_SCREENSHOT_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp"}
BANK_IMPORT_PRODUCT_CODE = "BIP"

# Bank Import Pro temporary statement storage. This MUST use a separate R2
# bucket from the central EXE/APK update bucket. The same R2 account or API
# token can be reused when it has permission for both buckets, but a separate
# token may be configured through the BANK_IMPORT_TEMP_R2_* variables.
BANK_IMPORT_TEMP_R2_ACCOUNT_ID = os.environ.get("BANK_IMPORT_TEMP_R2_ACCOUNT_ID", R2_ACCOUNT_ID).strip()
BANK_IMPORT_TEMP_R2_ACCESS_KEY_ID = os.environ.get("BANK_IMPORT_TEMP_R2_ACCESS_KEY_ID", R2_ACCESS_KEY_ID).strip()
BANK_IMPORT_TEMP_R2_SECRET_ACCESS_KEY = os.environ.get("BANK_IMPORT_TEMP_R2_SECRET_ACCESS_KEY", R2_SECRET_ACCESS_KEY).strip()
BANK_IMPORT_TEMP_R2_BUCKET_NAME = os.environ.get("BANK_IMPORT_TEMP_R2_BUCKET_NAME", "").strip()
BANK_IMPORT_TEMP_R2_ENDPOINT_URL = os.environ.get("BANK_IMPORT_TEMP_R2_ENDPOINT_URL", "").strip() or (
    f"https://{BANK_IMPORT_TEMP_R2_ACCOUNT_ID}.r2.cloudflarestorage.com" if BANK_IMPORT_TEMP_R2_ACCOUNT_ID else ""
)
BANK_IMPORT_TEMP_UPLOAD_URL_SECONDS = max(60, int(os.environ.get("BANK_IMPORT_TEMP_UPLOAD_URL_SECONDS", "900")))
BANK_IMPORT_TEMP_RETENTION_HOURS = max(1, int(os.environ.get("BANK_IMPORT_TEMP_RETENTION_HOURS", "24")))
MAX_BANK_IMPORT_PDF_MB = max(1, int(os.environ.get("MAX_BANK_IMPORT_PDF_MB", "30")))
# Customer portal opens the Bank Import Pro Flutter workspace in a separate
# full-screen browser tab. During private localhost testing keep this URL as
# http://localhost:7357. Change it to https://bankimport.tezhisab.com only
# after the Cloudflare Pages production frontend is ready.
BANK_IMPORT_WEB_APP_URL = os.environ.get("BANK_IMPORT_WEB_APP_URL", "http://localhost:7357").strip().rstrip("/")
BANK_IMPORT_LAUNCH_TICKET_SECONDS = max(30, min(int(os.environ.get("BANK_IMPORT_LAUNCH_TICKET_SECONDS", "120")), 600))
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# Flutter Web runs on a separate Cloudflare Pages domain. Allow the approved
# Bank Import Pro frontend origins and localhost preview origins to call the
# existing authenticated portal APIs. Set CORS_ALLOWED_ORIGINS in Render when
# additional production/staging domains are introduced.
CORS_ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "https://tezhisab.com,https://www.tezhisab.com,https://bankimport.tezhisab.com,https://preview-bankimport.tezhisab.com",
    ).split(",")
    if origin.strip()
}

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def _cors_origin_allowed(origin: str | None) -> bool:
    value = (origin or "").strip().rstrip("/")
    if not value:
        return False
    if value in CORS_ALLOWED_ORIGINS:
        return True
    # Keep local Flutter Chrome preview easy during development.
    return value.startswith("http://localhost:") or value.startswith("http://127.0.0.1:")


@app.after_request
def _add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    if _cors_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Max-Age"] = "86400"
    return response

DEFAULT_PRODUCTS = [
    {
        "product_name": "TallySync Pro",
        "product_code": "TSP",
        "prefix_code": "TSP",
        "default_limit": 3,
        "status": "active",
        "sort_order": 1,
    },
    {
        "product_name": "EPF & ESIC Manager",
        "product_code": "EEM",
        "prefix_code": "EEM",
        "default_limit": 3,
        "status": "active",
        "sort_order": 2,
    },
    {
        "product_name": "Bank Import Pro",
        "product_code": "BIP",
        "prefix_code": "BIP",
        "default_limit": 3,
        "status": "active",
        "sort_order": 3,
    },
    {
        "product_name": "TezHisab Prime / Invoice Management",
        "product_code": "THP",
        "prefix_code": "THP",
        "default_limit": 3,
        "status": "active",
        "sort_order": 4,
    },
    {
        "product_name": "EDU PRIME",
        "product_code": "EDUPRIME",
        "prefix_code": "EDPR",
        "default_limit": 2,
        "status": "active",
        "sort_order": 5,
    },
]


def today_str() -> str:
    return date.today().isoformat()



def days_from_today(d_str: str | None) -> int:
    if not d_str:
        return 9999
    try:
        exp = date.fromisoformat(d_str)
        return (exp - date.today()).days
    except Exception:
        return 0



def _normalize_email(value: str | None) -> str:
    return (value or "").strip().lower()


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 210_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def _verify_password(password: str, stored: str | None) -> bool:
    try:
        algorithm, iterations, salt, expected = (stored or "").split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _issue_token(user: dict[str, Any]) -> str:
    payload = {
        "email": _normalize_email(user.get("email")),
        "role": (user.get("role") or "customer").lower(),
        "customer_id": user.get("customer_id"),
        "name": user.get("display_name") or user.get("email") or "User",
        "exp": int(time.time()) + (SESSION_HOURS * 3600),
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}"


def _read_token(token: str | None) -> dict[str, Any] | None:
    try:
        body, signature = (token or "").split(".", 1)
        expected = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_b64decode(body).decode())
        if int(payload.get("exp") or 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def _current_user(req) -> dict[str, Any] | None:
    header = req.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return _read_token(header.split(" ", 1)[1].strip())
    return None


def check_admin(req) -> bool:
    # Keep the old dashboard working during migration. New portal uses signed bearer tokens.
    if req.headers.get("X-Admin-Token", "") == ADMIN_PASSWORD:
        return True
    user = _current_user(req)
    return bool(user and user.get("role") == "admin" and _normalize_email(user.get("email")) in ADMIN_EMAILS)


def _write_log(action: str, details: dict[str, Any] | None = None, req=None) -> None:
    try:
        user = _current_user(req) if req is not None else None
        supabase.table("activity_logs").insert({
            "actor_email": (user or {}).get("email") or "system",
            "actor_role": (user or {}).get("role") or "system",
            "action": action,
            "details": details or {},
        }).execute()
    except Exception:
        # Logging must never interrupt licensing.
        pass




def _r2_is_configured() -> bool:
    return bool(boto3 and BotoConfig and R2_ENDPOINT_URL and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_BUCKET_NAME)


def _r2_client():
    if not _r2_is_configured():
        raise RuntimeError("Cloud storage is not configured. Add the R2 Environment Variables in Render first.")
    return boto3.client(
        service_name="s3",
        endpoint_url=R2_ENDPOINT_URL,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
        config=BotoConfig(signature_version="s3v4"),
    )


def _bank_import_temp_r2_is_configured() -> bool:
    return bool(
        boto3
        and BotoConfig
        and BANK_IMPORT_TEMP_R2_ENDPOINT_URL
        and BANK_IMPORT_TEMP_R2_ACCESS_KEY_ID
        and BANK_IMPORT_TEMP_R2_SECRET_ACCESS_KEY
        and BANK_IMPORT_TEMP_R2_BUCKET_NAME
        and BANK_IMPORT_TEMP_R2_BUCKET_NAME != R2_BUCKET_NAME
    )


def _bank_import_temp_r2_client():
    if not _bank_import_temp_r2_is_configured():
        if BANK_IMPORT_TEMP_R2_BUCKET_NAME and BANK_IMPORT_TEMP_R2_BUCKET_NAME == R2_BUCKET_NAME:
            raise RuntimeError("Bank Import temporary PDFs must use a separate R2 bucket from EXE/APK updates.")
        raise RuntimeError("Temporary Bank Import PDF storage is not configured. Add BANK_IMPORT_TEMP_R2_BUCKET_NAME in Render first.")
    return boto3.client(
        service_name="s3",
        endpoint_url=BANK_IMPORT_TEMP_R2_ENDPOINT_URL,
        aws_access_key_id=BANK_IMPORT_TEMP_R2_ACCESS_KEY_ID,
        aws_secret_access_key=BANK_IMPORT_TEMP_R2_SECRET_ACCESS_KEY,
        region_name="auto",
        config=BotoConfig(signature_version="s3v4"),
    )


def _safe_app_filename(filename: str) -> str:
    clean = secure_filename(filename or "")
    if not clean:
        raise ValueError("Select a valid EXE, APK, MSI or ZIP file.")
    suffix = Path(clean).suffix.lower()
    if suffix not in ALLOWED_APP_EXTENSIONS:
        raise ValueError("Only EXE, APK, MSI and ZIP files are allowed.")
    return clean


def _clean_path_piece(value: Any, fallback: str = "item") -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return clean[:80] or fallback


def _edition_code(value: Any) -> str:
    clean = re.sub(r"[^A-Za-z0-9]+", "", str(value or "").upper())
    return clean[:32] or "STANDARD"


def _new_storage_key(channel: dict[str, Any], version: str, filename: str, edition_code: str = "STANDARD") -> str:
    product = _clean_path_piece(channel.get("product_code"), "software").lower()
    channel_code = _clean_path_piece(channel.get("channel_code"), "channel").lower()
    edition_piece = _clean_path_piece(_edition_code(edition_code), "standard").lower()
    version_piece = _clean_path_piece(version, "version")
    safe_name = _safe_app_filename(filename)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    random_piece = secrets.token_hex(4)
    return f"apps/{product}/{edition_piece}/{channel_code}/{version_piece}/{stamp}_{random_piece}_{safe_name}"


def _safe_requirement_filename(filename: str) -> str:
    clean = secure_filename(filename or "")
    if not clean:
        raise ValueError("Select a valid PDF, image, document, spreadsheet or ZIP file.")
    suffix = Path(clean).suffix.lower()
    if suffix not in ALLOWED_REQUIREMENT_EXTENSIONS:
        raise ValueError("Allowed attachments: PDF, image, Word, Excel, CSV, TXT or ZIP.")
    return clean



def _safe_bank_import_pdf_filename(filename: str) -> str:
    clean = secure_filename(filename or "")
    if not clean:
        raise ValueError("Select a valid PDF bank statement.")
    if Path(clean).suffix.lower() != ".pdf":
        raise ValueError("Only original PDF bank statements are allowed.")
    return clean


def _new_bank_import_temp_storage_key(customer_id: int, email: str, filename: str) -> str:
    customer_piece = _clean_path_piece(customer_id or _normalize_email(email).replace("@", "-at-"), "customer").lower()
    safe_name = _safe_bank_import_pdf_filename(filename)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    day_piece = datetime.utcnow().strftime("%Y/%m/%d")
    return f"statements/{customer_piece}/{day_piece}/{stamp}_{secrets.token_hex(8)}_{safe_name}"


def _bank_import_temp_presigned_put(storage_key: str, expires: int | None = None) -> str:
    return _bank_import_temp_r2_client().generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": BANK_IMPORT_TEMP_R2_BUCKET_NAME, "Key": storage_key, "ContentType": "application/pdf"},
        ExpiresIn=max(60, min(int(expires or BANK_IMPORT_TEMP_UPLOAD_URL_SECONDS), 3600)),
    )


def _issue_bank_import_temp_upload_ticket(upload_id: int, storage_key: str, customer_id: int, email: str, size_bytes: int) -> str:
    payload = {
        "upload_id": int(upload_id),
        "storage_key": storage_key,
        "customer_id": int(customer_id),
        "email": _normalize_email(email),
        "size_bytes": int(size_bytes),
        "exp": int(time.time()) + BANK_IMPORT_TEMP_UPLOAD_URL_SECONDS,
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def _read_bank_import_temp_upload_ticket(ticket: str | None, customer_id: int, email: str) -> dict[str, Any] | None:
    try:
        body, sig = (ticket or "").split(".", 1)
        expected = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64decode(body).decode())
        if int(payload.get("exp") or 0) < int(time.time()):
            return None
        if int(payload.get("customer_id") or 0) != int(customer_id):
            return None
        if _normalize_email(payload.get("email")) != _normalize_email(email):
            return None
        if not (payload.get("storage_key") or "").startswith("statements/"):
            return None
        return payload
    except Exception:
        return None


def _delete_bank_import_temp_object(storage_key: str) -> tuple[bool, str]:
    key = (storage_key or "").strip()
    if not key.startswith("statements/"):
        return False, "Invalid temporary statement storage key."
    try:
        _bank_import_temp_r2_client().delete_object(Bucket=BANK_IMPORT_TEMP_R2_BUCKET_NAME, Key=key)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _safe_bank_import_temp_upload(row: dict[str, Any] | None) -> dict[str, Any]:
    item = dict(row or {})
    return {
        "id": item.get("id"),
        "filename": item.get("original_filename") or "Bank statement.pdf",
        "content_type": item.get("content_type") or "application/pdf",
        "size_bytes": int(item.get("size_bytes") or 0),
        "status": item.get("status") or "unknown",
        "created_at": item.get("created_at"),
        "uploaded_at": item.get("uploaded_at"),
        "deleted_at": item.get("deleted_at"),
        "expires_at": item.get("expires_at"),
        "page_count": int(item.get("page_count") or 0),
        "wallet_pages_reserved": int(item.get("wallet_pages_reserved") or 0),
        "wallet_pages_charged": int(item.get("wallet_pages_charged") or 0),
    }


def _cleanup_expired_bank_import_temp_uploads(limit: int = 30) -> dict[str, Any]:
    result: dict[str, Any] = {"checked": 0, "deleted": 0, "failed": 0, "reservations_released": 0}
    if not _bank_import_temp_r2_is_configured():
        result["message"] = "Temporary Bank Import PDF storage is not configured."
        return result
    try:
        rows = (
            supabase.table("bank_import_temp_uploads")
            .select("*")
            .in_("status", ["upload_url_created", "uploaded", "processing", "failed"])
            .lt("expires_at", datetime.utcnow().isoformat())
            .order("expires_at")
            .limit(max(1, min(int(limit), 200)))
            .execute()
            .data
            or []
        )
    except Exception as exc:
        result["message"] = str(exc)
        return result
    for row in rows:
        result["checked"] += 1
        reservation_id = int(row.get("reservation_id") or 0)
        if reservation_id:
            released, _ = _release_bank_import_reservation(reservation_id, "Temporary PDF expired before processing completed.")
            if released:
                result["reservations_released"] += 1
        ok, error = _delete_bank_import_temp_object(row.get("storage_key") or "")
        payload = {"status": "expired", "deleted_at": datetime.utcnow().isoformat()} if ok else {"status": "failed", "failure_reason": error[:500]}
        try:
            supabase.table("bank_import_temp_uploads").update(payload).eq("id", int(row.get("id") or 0)).execute()
        except Exception:
            pass
        if ok:
            result["deleted"] += 1
        else:
            result["failed"] += 1
    return result


def _safe_recharge_screenshot_filename(filename: str) -> str:
    clean = secure_filename(filename or "")
    if not clean:
        raise ValueError("Select a valid payment screenshot or PDF receipt.")
    suffix = Path(clean).suffix.lower()
    if suffix not in ALLOWED_RECHARGE_SCREENSHOT_EXTENSIONS:
        raise ValueError("Allowed payment proofs: PNG, JPG, WEBP or PDF.")
    return clean


def _new_recharge_screenshot_storage_key(email: str, filename: str) -> str:
    customer_piece = _clean_path_piece(_normalize_email(email).replace("@", "-at-"), "customer").lower()
    safe_name = _safe_recharge_screenshot_filename(filename)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"bank-import/recharge-proofs/{customer_piece}/{stamp}_{secrets.token_hex(4)}_{safe_name}"

def _new_requirement_storage_key(email: str, filename: str) -> str:
    customer_piece = _clean_path_piece(_normalize_email(email).replace("@", "-at-"), "visitor").lower()
    safe_name = _safe_requirement_filename(filename)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"requirements/{customer_piece}/{stamp}_{secrets.token_hex(4)}_{safe_name}"


def _r2_presigned_get(storage_key: str, expires: int | None = None) -> str:
    return _r2_client().generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": R2_BUCKET_NAME, "Key": storage_key},
        ExpiresIn=max(60, min(int(expires or R2_SIGNED_URL_SECONDS), 604800)),
    )


def _r2_presigned_put(storage_key: str, content_type: str, expires: int | None = None) -> str:
    return _r2_client().generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": R2_BUCKET_NAME, "Key": storage_key, "ContentType": content_type},
        ExpiresIn=max(60, min(int(expires or R2_UPLOAD_URL_SECONDS), 604800)),
    )


def _delete_cloud_version(version: dict[str, Any]) -> tuple[bool, str]:
    """Delete one centrally stored installer and its version metadata safely."""
    version_id = int(version.get("id") or 0)
    storage_key = (version.get("storage_key") or "").strip()
    try:
        if storage_key:
            if not _r2_is_configured():
                return False, "Cloud storage is not configured."
            _r2_client().delete_object(Bucket=R2_BUCKET_NAME, Key=storage_key)
        if version_id:
            supabase.table("app_versions").delete().eq("id", version_id).execute()
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _cleanup_old_cloud_versions(channel_id: int, keep_count: int | None = None, edition_id: int | None = None) -> dict[str, Any]:
    """Keep the newest cloud files separately for each software edition."""
    keep = max(1, int(keep_count or APP_VERSION_RETENTION_COUNT))
    query = (
        supabase.table("app_versions")
        .select("*")
        .eq("channel_id", int(channel_id))
        .eq("published", True)
        .order("created_at", desc=True)
    )
    if edition_id is not None:
        query = query.eq("edition_id", int(edition_id))
    rows = query.execute().data or []
    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        group_id = int(row.get("edition_id") or 0)
        grouped.setdefault(group_id, []).append(row)
    removed: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for group_id, group_rows in grouped.items():
        cloud_rows = [row for row in group_rows if (row.get("storage_key") or "").strip()]
        for row in cloud_rows[keep:]:
            ok, error = _delete_cloud_version(row)
            item = {"id": row.get("id"), "version": row.get("version"), "edition_id": group_id or None, "storage_key": row.get("storage_key")}
            if ok:
                removed.append(item)
            else:
                item["error"] = error
                failed.append(item)
    return {"channel_id": int(channel_id), "edition_id": edition_id, "keep_count": keep, "removed": removed, "failed": failed}


def _cleanup_all_cloud_versions(keep_count: int | None = None) -> dict[str, Any]:
    keep = max(1, int(keep_count or APP_VERSION_RETENTION_COUNT))
    channels = supabase.table("update_channels").select("id").execute().data or []
    results = [_cleanup_old_cloud_versions(int(row.get("id") or 0), keep) for row in channels if row.get("id")]
    return {
        "keep_count": keep,
        "removed_count": sum(len(item["removed"]) for item in results),
        "failed_count": sum(len(item["failed"]) for item in results),
        "results": results,
    }


def _fetch_edition(edition_id: Any) -> dict[str, Any] | None:
    try:
        edition_id = int(edition_id or 0)
    except Exception:
        edition_id = 0
    if not edition_id:
        return None
    try:
        rows = supabase.table("product_editions").select("*").eq("id", edition_id).limit(1).execute().data or []
        return rows[0] if rows else None
    except Exception:
        return None


def _edition_summary(edition: dict[str, Any] | None) -> dict[str, Any]:
    if not edition:
        return {"id": None, "edition_code": "STANDARD", "edition_name": "Standard Edition", "release_scope": "standard"}
    return {
        "id": edition.get("id"),
        "edition_code": _edition_code(edition.get("edition_code")),
        "edition_name": (edition.get("edition_name") or "Custom Edition").strip(),
        "release_scope": (edition.get("release_scope") or "customer_specific").strip(),
        "customer_id": edition.get("customer_id"),
        "status": edition.get("status") or "active",
    }


def _edition_for_license(license_row: dict[str, Any] | None) -> dict[str, Any]:
    return _edition_summary(_fetch_edition((license_row or {}).get("edition_id")))


def _verify_turnstile(token: str | None, remote_ip: str | None = None) -> tuple[bool, str]:
    """Verify Cloudflare Turnstile only when it is configured in Render."""
    if not TURNSTILE_SECRET_KEY:
        return True, "Turnstile is not configured; registration remains available."
    if not token:
        return False, "Please complete the security verification."
    try:
        form = {"secret": TURNSTILE_SECRET_KEY, "response": token}
        if remote_ip:
            form["remoteip"] = remote_ip
        req = urllib_request.Request(TURNSTILE_VERIFY_URL, data=urllib_parse.urlencode(form).encode(), method="POST")
        with urllib_request.urlopen(req, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return bool(payload.get("success")), "" if payload.get("success") else "Security verification failed. Please refresh and try again."
    except Exception:
        return False, "Security verification could not be completed. Please try again."

def _portal_user_from_request(req) -> dict[str, Any] | None:
    return _current_user(req) or _read_token(req.args.get("token"))


def _version_response(version: dict[str, Any] | None, include_presigned_download: bool = False) -> dict[str, Any] | None:
    if not version:
        return None
    item = dict(version)
    item["edition"] = _edition_summary(_fetch_edition(item.get("edition_id")))
    storage_key = (item.get("storage_key") or "").strip()
    if storage_key:
        item["delivery_mode"] = "central_cloud"
        item["download_url"] = _r2_presigned_get(storage_key) if include_presigned_download and _r2_is_configured() else ""
        item["download_requires_login"] = not include_presigned_download
    else:
        item["delivery_mode"] = "external_link"
        item["download_requires_login"] = False
    return item


def _active_license_for_email_product(email: str, product_code: str) -> dict[str, Any] | None:
    rows = supabase.table("licenses").select("*").eq("client_email", _normalize_email(email)).execute().data or []
    for row in rows:
        lic = enrich_license(row)
        if lic.get("product_code") != normalize_product(product_code):
            continue
        if lic.get("status") == "suspended" or lic.get("days_left", -1) < 0:
            continue
        return lic
    return None


def _active_license_for_email_product_edition(email: str, product_code: str, edition_id: Any = None) -> dict[str, Any] | None:
    rows = supabase.table("licenses").select("*").eq("client_email", _normalize_email(email)).execute().data or []
    for row in rows:
        lic = enrich_license(row)
        if lic.get("product_code") != normalize_product(product_code):
            continue
        if int(lic.get("edition_id") or 0) != int(edition_id or 0):
            continue
        if lic.get("status") == "suspended" or lic.get("days_left", -1) < 0:
            continue
        return lic
    return None


def slug_code(value: str) -> str:
    """Normalize compact product/license codes. Product codes remain short for compatibility."""
    cleaned = "".join(ch for ch in value.upper().strip() if ch.isalnum())
    return cleaned[:8]


def channel_slug(value: str | None) -> str:
    """Normalize update-channel codes without truncating values such as WINDOWS_EXE.

    Older builds sent values like WINDOWS_EXE while seeded database rows use
    WINDOWSEXE. Previous generic slug_code() truncated the value to WINDOWSE,
    causing secure updater lookups to miss the published channel and silently
    fall back to an older local manifest. Keep aliases for backward compatibility.
    """
    cleaned = "".join(ch for ch in str(value or "").upper().strip() if ch.isalnum())
    aliases = {
        "WINDOWS": "WINDOWSEXE",
        "WINDOWSE": "WINDOWSEXE",
        "WINDOWSEXE": "WINDOWSEXE",
        "WINDOWSDESKTOPEXE": "WINDOWSEXE",
        "ANDROID": "ANDROIDAPK",
        "ANDROIDAP": "ANDROIDAPK",
        "ANDROIDAPK": "ANDROIDAPK",
        "ANDROIDMOBILEAPK": "ANDROIDAPK",
        "WEB": "WEBAPP",
        "WEBAPP": "WEBAPP",
    }
    return aliases.get(cleaned, cleaned[:32])



def make_checksum(raw: str) -> str:
    return hmac.new(SERVER_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:4].upper()



def verify_key_format(key: str) -> bool:
    parts = key.strip().upper().split("-")
    if len(parts) != 6:
        return False
    raw = "-".join(parts[:5])
    return parts[5] == make_checksum(raw)



def make_signature(key: str, machine_id: str, expires: str) -> str:
    payload = f"{key}|{machine_id}|{expires}|{SERVER_SECRET}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]



def _safe_table_select(table: str, *cols: str, order_by: str | None = None):
    query = supabase.table(table).select(",".join(cols) if cols else "*")
    if order_by:
        query = query.order(order_by)
    return query.execute()



def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _normalize_product_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Return one clean/canonical product row.

    product_code is the canonical code used by apps and licenses.
    product_name and prefix_code are display/key-prefix helpers.
    Values such as EDU PRIME, EDU_PRIME and EDUPRIME compare as EDUPRIME.
    """
    code = slug_code(row.get("product_code") or row.get("code") or row.get("prefix_code") or row.get("product_name") or "")
    if not code:
        return None
    return {
        "id": row.get("id"),
        "product_name": (row.get("product_name") or row.get("name") or code).strip(),
        "product_code": code,
        "prefix_code": slug_code(row.get("prefix_code") or code) or code,
        "default_limit": _int_or_default(row.get("default_limit"), 3),
        "status": (row.get("status") or "active").lower(),
        "sort_order": _int_or_default(row.get("sort_order"), 999),
        "description": (row.get("description") or "").strip(),
        "auto_update_required": bool(row.get("auto_update_required", True)),
        "customer_portal_visible": bool(row.get("customer_portal_visible", True)),
    }


def fetch_products() -> list[dict[str, Any]]:
    try:
        resp = _safe_table_select("products", "*", order_by="sort_order")
        rows = resp.data or []
    except Exception:
        rows = []

    source_rows = rows if rows else DEFAULT_PRODUCTS.copy()
    by_code: dict[str, dict[str, Any]] = {}
    for row in source_rows:
        product = _normalize_product_row(row)
        if not product:
            continue
        code = product["product_code"]
        old = by_code.get(code)
        if old is None:
            by_code[code] = product
            continue
        old_rank = (old.get("status") != "active", old.get("sort_order", 999), old.get("id") or 10**18)
        new_rank = (product.get("status") != "active", product.get("sort_order", 999), product.get("id") or 10**18)
        if new_rank < old_rank:
            by_code[code] = product

    products = list(by_code.values())
    products.sort(key=lambda x: (x.get("sort_order", 999), x["product_name"]))
    return products


def get_product_map(include_inactive: bool = True) -> dict[str, dict[str, Any]]:
    products = fetch_products()
    if not include_inactive:
        products = [p for p in products if p.get("status") == "active"]
    return {p["product_code"]: p for p in products}


def build_product_alias_map(include_inactive: bool = True) -> dict[str, dict[str, Any]]:
    """Map product_code, product_name slug and prefix_code to canonical product.

    This prevents future product mismatches when a new app uses slightly
    different spacing/underscore/case from the admin UI.
    """
    alias_map: dict[str, dict[str, Any]] = {}
    for p in fetch_products():
        if not include_inactive and p.get("status") != "active":
            continue
        for alias in (p.get("product_code"), p.get("product_name"), p.get("prefix_code")):
            code = slug_code(alias or "")
            if code and code not in alias_map:
                alias_map[code] = p
        # Exact/canonical product code wins.
        alias_map[p["product_code"]] = p
    return alias_map


def find_product(product: str | None, include_inactive: bool = True) -> dict[str, Any] | None:
    code = slug_code(product or "")
    if not code:
        code = DEFAULT_PRODUCT_CODE
    return build_product_alias_map(include_inactive=include_inactive).get(code)


def normalize_product(product: str | None) -> str:
    p = find_product(product, include_inactive=True)
    if p:
        return p["product_code"]
    code = slug_code(product or "")
    return code or DEFAULT_PRODUCT_CODE


def generate_key(product_code: str) -> str:
    product_map = get_product_map(include_inactive=True)
    product = product_map.get(product_code)
    prefix = (product or {}).get("prefix_code") or product_code or "GEN"
    year = datetime.now().year
    part1 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    part2 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    raw = f"{LICENSE_PREFIX}-{prefix}-{year}-{part1}-{part2}"
    return f"{raw}-{make_checksum(raw)}"



def enrich_license(lic: dict[str, Any], product_map: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    product_map = product_map or get_product_map(include_inactive=True)
    code = normalize_product(lic.get("product") or lic.get("product_code"))
    product = product_map.get(code, {"product_name": code, "product_code": code, "default_limit": 3})
    days_left = days_from_today(lic.get("expires_on"))
    display_status = "active"
    if (lic.get("status") or "active").lower() == "suspended":
        display_status = "suspended"
    elif days_left < 0:
        display_status = "expired"
    elif days_left <= 30:
        display_status = "expiring_soon"
    enriched = dict(lic)
    enriched["product"] = code
    enriched["product_code"] = code
    enriched["product_name"] = product.get("product_name", code)
    enriched["default_limit"] = int(product.get("default_limit") or 3)
    enriched["days_left"] = days_left
    enriched["display_status"] = display_status
    enriched["used_pcs"] = len(enriched.get("machines") or [])
    edition = _edition_for_license(enriched)
    enriched["edition_id"] = edition.get("id")
    enriched["edition_code"] = edition.get("edition_code")
    enriched["edition_name"] = edition.get("edition_name")
    enriched["release_scope"] = edition.get("release_scope")
    return enriched



def get_license_by_key(key: str) -> dict[str, Any] | None:
    resp = supabase.table("licenses").select("*").eq("key", key).execute()
    if not resp.data:
        return None
    return enrich_license(resp.data[0])


@app.route("/")
def index():
    return send_from_directory("admin", "portal.html")


@app.route("/portal")
@app.route("/portal/")
def portal():
    return send_from_directory("admin", "portal.html")


@app.route("/legacy-admin")
def legacy_admin():
    return send_from_directory("admin", "index.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    if data.get("password") == ADMIN_PASSWORD:
        return jsonify({"success": True, "token": ADMIN_PASSWORD, "brand": BRAND_NAME})
    return jsonify({"success": False, "message": "Invalid password"}), 401


@app.route("/admin/products", methods=["GET"])
def admin_products():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    return jsonify({"success": True, "products": fetch_products(), "brand": BRAND_NAME, "license_prefix": LICENSE_PREFIX})


@app.route("/admin/products", methods=["POST"])
def admin_add_product():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.json or {}
    product_name = (data.get("product_name") or "").strip()
    product_code = slug_code(data.get("product_code") or "")
    prefix_code = slug_code(data.get("prefix_code") or product_code)
    status = (data.get("status") or "active").lower()
    default_limit = int(data.get("default_limit") or 3)
    if not product_name or not product_code:
        return jsonify({"success": False, "message": "Product name and code are required."}), 400
    existing = get_product_map(include_inactive=True)
    if product_code in existing:
        return jsonify({"success": False, "message": "Product code already exists."}), 400
    payload = {
        "product_name": product_name,
        "product_code": product_code,
        "prefix_code": prefix_code or product_code,
        "default_limit": default_limit,
        "status": status,
        "sort_order": int(data.get("sort_order") or (len(existing) + 1)),
    }
    try:
        supabase.table("products").insert(payload).execute()
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Could not save product. Create a 'products' table in Supabase with columns: product_name, product_code, prefix_code, default_limit, status, sort_order.",
            "error": str(e),
        }), 500
    return jsonify({"success": True, "message": "Product added successfully.", "product": payload})


@app.route("/admin/products/<product_code>", methods=["PUT"])
def admin_update_product(product_code: str):
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    code = slug_code(product_code)
    data = request.json or {}
    payload = {}
    if "product_name" in data:
        payload["product_name"] = (data.get("product_name") or "").strip()
    if "prefix_code" in data:
        payload["prefix_code"] = slug_code(data.get("prefix_code") or code) or code
    if "default_limit" in data:
        payload["default_limit"] = int(data.get("default_limit") or 3)
    if "status" in data:
        payload["status"] = (data.get("status") or "active").lower()
    if not payload:
        return jsonify({"success": False, "message": "No changes provided."}), 400
    try:
        supabase.table("products").update(payload).eq("product_code", code).execute()
    except Exception as e:
        return jsonify({"success": False, "message": "Could not update product.", "error": str(e)}), 500
    return jsonify({"success": True, "message": "Product updated successfully."})




@app.route("/admin/products/<product_code>", methods=["DELETE"])
def admin_delete_product(product_code: str):
    """Delete a product from Manage Products.

    Default behaviour is safe: if licenses exist for this product, the delete
    is blocked and the UI asks for confirmation. If force=true is sent, matching
    licenses are also deleted. Use this only for test/unwanted products.
    """
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    code = slug_code(product_code)
    force = str(request.args.get("force", "")).lower() in ("1", "true", "yes")
    if not code:
        return jsonify({"success": False, "message": "Product code required."}), 400

    # Never allow deletion of built-in/core products unless explicitly forced.
    # This prevents accidental deletion of running products such as Bank Import Pro.
    built_in_codes = {slug_code(p.get("product_code", "")) for p in DEFAULT_PRODUCTS}

    try:
        lic_resp = supabase.table("licenses").select("key,product,client_name").eq("product", code).execute()
        matching_licenses = lic_resp.data or []
    except Exception as e:
        return jsonify({"success": False, "message": "Could not check product licenses before delete.", "error": str(e)}), 500

    if matching_licenses and not force:
        return jsonify({
            "success": False,
            "requires_force": True,
            "license_count": len(matching_licenses),
            "message": f"This product has {len(matching_licenses)} license(s). Delete again with force only if these are test/unwanted licenses.",
        }), 409

    try:
        if matching_licenses and force:
            supabase.table("licenses").delete().eq("product", code).execute()

        # Delete exact product_code row first. This is the normal path.
        supabase.table("products").delete().eq("product_code", code).execute()

        # Also remove common duplicate/dirty rows that normalize to the same slug.
        # Supabase cannot filter by our Python slug function, so we fetch and delete by id.
        try:
            prod_resp = supabase.table("products").select("id,product_name,product_code,prefix_code").execute()
            for row in (prod_resp.data or []):
                aliases = [row.get("product_code"), row.get("product_name"), row.get("prefix_code")]
                if any(slug_code(a or "") == code for a in aliases):
                    row_id = row.get("id")
                    if row_id is not None:
                        supabase.table("products").delete().eq("id", row_id).execute()
                    else:
                        supabase.table("products").delete().eq("product_code", row.get("product_code") or code).execute()
        except Exception:
            # The exact delete above already ran; ignore cleanup errors for old schemas.
            pass
    except Exception as e:
        return jsonify({"success": False, "message": "Could not delete product.", "error": str(e)}), 500

    return jsonify({
        "success": True,
        "message": "Product deleted successfully." + (" Matching licenses were also deleted." if matching_licenses and force else ""),
        "deleted_product_code": code,
        "deleted_license_count": len(matching_licenses) if force else 0,
        "built_in_product": code in built_in_codes,
    })


@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    key = (data.get("key") or "").strip().upper()
    machine_id = (data.get("machine_id") or "").strip()
    machine_label = (data.get("machine_label") or "Unknown PC").strip()
    product = find_product(data.get("product"), include_inactive=True)
    product_code = product["product_code"] if product else normalize_product(data.get("product"))

    if not key or not machine_id:
        return jsonify({"success": False, "message": "Key and Machine ID are required."}), 400
    if not product:
        return jsonify({"success": False, "message": f"Product is not registered on license server: {product_code}. Add it from Manage Products, then generate a license for that product."}), 400
    if not verify_key_format(key):
        return jsonify({"success": False, "message": "Invalid license key format."}), 400

    lic = get_license_by_key(key)
    if not lic:
        return jsonify({"success": False, "message": "License key not found."}), 404
    if lic["product_code"] != product_code:
        return jsonify({"success": False, "message": f"This license is not valid for product: {product_code}"}), 403
    if (lic.get("status") or "active").lower() not in ("active", "trial"):
        return jsonify({"success": False, "message": "This license is suspended. Please contact Tezhisab support."}), 403

    days_left = lic["days_left"]
    if days_left < 0:
        return jsonify({"success": False, "message": f"This license expired on {lic.get('expires_on')}. Please renew."}), 403

    machines = lic.get("machines") or []
    max_pcs = int(lic.get("max_pcs") or lic.get("default_limit") or 3)
    existing_ids = [m.get("id") for m in machines]
    if machine_id in existing_ids:
        sig = make_signature(key, machine_id, lic.get("expires_on", ""))
        return jsonify({
            "success": True,
            "message": "Already activated on this machine.",
            "expires": lic.get("expires_on", ""),
            "client_name": lic.get("client_name", ""),
            "days_left": days_left,
            "product": product_code,
            "signature": sig,
        })
    if len(machines) >= max_pcs:
        return jsonify({"success": False, "message": f"Maximum {max_pcs} PC limit reached for this license."}), 403

    machines.append({"id": machine_id, "label": machine_label, "activated_on": today_str()})
    supabase.table("licenses").update({"machines": machines, "last_verified": today_str(), "product": product_code}).eq("key", key).execute()
    sig = make_signature(key, machine_id, lic.get("expires_on", ""))
    return jsonify({
        "success": True,
        "message": "License activated successfully!",
        "expires": lic.get("expires_on", ""),
        "client_name": lic.get("client_name", ""),
        "days_left": days_left,
        "product": product_code,
        "signature": sig,
    })


@app.route("/verify", methods=["POST"])
def verify():
    data = request.json or {}
    key = (data.get("key") or "").strip().upper()
    machine_id = (data.get("machine_id") or "").strip()
    product = find_product(data.get("product"), include_inactive=True)
    product_code = product["product_code"] if product else normalize_product(data.get("product"))

    if not key or not machine_id:
        return jsonify({"valid": False, "message": "Missing key or machine ID."}), 400
    if not product:
        return jsonify({"valid": False, "message": f"Product is not registered on license server: {product_code}. Add it from Manage Products, then generate a license for that product."}), 400

    lic = get_license_by_key(key)
    if not lic:
        return jsonify({"valid": False, "message": "License key not found."}), 404
    if lic["product_code"] != product_code:
        return jsonify({"valid": False, "message": f"This license is not valid for product: {product_code}"}), 403
    if (lic.get("status") or "active").lower() not in ("active", "trial"):
        return jsonify({"valid": False, "message": "This license is suspended. Please contact Tezhisab support."}), 403

    machines = lic.get("machines") or []
    if machine_id not in [m.get("id") for m in machines]:
        return jsonify({"valid": False, "message": "This machine is not registered for this license. Please activate first."}), 403
    if lic["days_left"] < 0:
        return jsonify({"valid": False, "message": f"License expired on {lic.get('expires_on')}. Please renew.", "expires": lic.get("expires_on"), "days_left": lic["days_left"]}), 403

    supabase.table("licenses").update({"last_verified": today_str(), "product": product_code}).eq("key", key).execute()
    return jsonify({
        "valid": True,
        "expires": lic.get("expires_on", ""),
        "client_name": lic.get("client_name", ""),
        "product": product_code,
        "days_left": lic["days_left"],
        "signature": make_signature(key, machine_id, lic.get("expires_on", "")),
        "message": "License valid.",
    })


@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.json or {}
    client_name = (data.get("client_name") or "").strip()
    client_phone = (data.get("client_phone") or "").strip()
    client_email = (data.get("client_email") or "").strip()
    notes = (data.get("notes") or "").strip()
    license_mode = (data.get("license_mode") or "standard").strip().lower()
    try:
        validity_days = int(data.get("validity_days") or (365 if license_mode == "standard" else 7))
    except Exception:
        validity_days = 365 if license_mode == "standard" else 7
    if license_mode not in ("standard", "trial"):
        return jsonify({"success": False, "message": "License type must be standard or trial."}), 400
    if validity_days < 1 or validity_days > 3650:
        return jsonify({"success": False, "message": "Validity days must be between 1 and 3650."}), 400
    product = find_product(data.get("product"), include_inactive=True)
    product_code = product["product_code"] if product else normalize_product(data.get("product"))
    product_map = get_product_map(include_inactive=True)
    if not client_name:
        return jsonify({"success": False, "message": "Client name required."}), 400
    if not product:
        return jsonify({"success": False, "message": f"Product is not registered on license server: {product_code}. Add it from Manage Products first."}), 400
    max_pcs = int(data.get("max_pcs") or product.get("default_limit") or 3)
    edition = _fetch_edition(data.get("edition_id"))
    if edition and normalize_product(edition.get("product_code")) != product_code:
        return jsonify({"success": False, "message": "Selected custom edition does not belong to this software product."}), 400
    key = generate_key(product_code)
    activated_on = today_str()
    expires_on = (date.today() + timedelta(days=validity_days)).isoformat()
    saved_status = "trial" if license_mode == "trial" else "active"
    notes_with_type = notes
    if license_mode == "trial":
        trial_note = f"TRIAL LICENSE — {validity_days} day(s)"
        notes_with_type = f"{trial_note} | {notes}" if notes else trial_note
    supabase.table("licenses").insert({
        "key": key,
        "product": product_code,
        "client_name": client_name,
        "client_phone": client_phone,
        "client_email": client_email,
        "max_pcs": max_pcs,
        "machines": [],
        "activated_on": activated_on,
        "expires_on": expires_on,
        "last_verified": None,
        "status": saved_status,
        "notes": notes_with_type,
        "edition_id": (edition or {}).get("id"),
    }).execute()
    return jsonify({
        "success": True,
        "key": key,
        "product": product_code,
        "product_name": product["product_name"],
        "expires_on": expires_on,
        "license_mode": license_mode,
        "validity_days": validity_days,
        "edition": _edition_summary(edition),
        "message": f"{'Trial key' if license_mode == 'trial' else 'License'} generated for {client_name}",
    })


@app.route("/admin/licenses", methods=["GET"])
def admin_licenses():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    raw_product = normalize_product(request.args.get("product")) if request.args.get("product") else ""
    try:
        query = supabase.table("licenses").select("*")
        if raw_product:
            query = query.eq("product", raw_product)
        resp = query.order("activated_on", desc=True).execute()
        licenses = [enrich_license(row) for row in (resp.data or [])]
    except Exception as e:
        return jsonify({"success": False, "message": "Failed to fetch licenses.", "error": str(e)}), 500
    return jsonify({"success": True, "licenses": licenses})


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    resp = supabase.table("licenses").select("*").execute()
    licenses = [enrich_license(row) for row in (resp.data or [])]
    products = fetch_products()
    total = len(licenses)
    active = sum(1 for l in licenses if l["display_status"] == "active")
    expiring = sum(1 for l in licenses if l["display_status"] == "expiring_soon")
    expired = sum(1 for l in licenses if l["display_status"] == "expired")
    total_pcs = sum(l["used_pcs"] for l in licenses)
    product_summaries = []
    for product in products:
        product_licenses = [l for l in licenses if l["product_code"] == product["product_code"]]
        product_summaries.append({
            "product_code": product["product_code"],
            "product_name": product["product_name"],
            "active": sum(1 for l in product_licenses if l["display_status"] == "active"),
            "expiring": sum(1 for l in product_licenses if l["display_status"] == "expiring_soon"),
            "expired": sum(1 for l in product_licenses if l["display_status"] == "expired"),
            "total": len(product_licenses),
            "used_pcs": sum(l["used_pcs"] for l in product_licenses),
        })
    expiring_list = sorted([l for l in licenses if 0 <= l["days_left"] <= 30], key=lambda x: x["days_left"])[:12]
    return jsonify({
        "success": True,
        "brand": BRAND_NAME,
        "license_prefix": LICENSE_PREFIX,
        "total": total,
        "active": active,
        "expiring_soon": expiring,
        "expired": expired,
        "total_pcs_activated": total_pcs,
        "product_summaries": product_summaries,
        "expiring_list": expiring_list,
    })


@app.route("/admin/renew", methods=["POST"])
def admin_renew():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    key = (request.json or {}).get("key", "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key required."}), 400
    lic = get_license_by_key(key)
    if not lic:
        return jsonify({"success": False, "message": "Key not found."}), 404
    try:
        base = date.fromisoformat(lic.get("expires_on") or today_str())
        if base < date.today():
            base = date.today()
    except Exception:
        base = date.today()
    new_expires = (base + timedelta(days=365)).isoformat()
    supabase.table("licenses").update({"expires_on": new_expires, "status": "active"}).eq("key", key).execute()
    return jsonify({"success": True, "message": f"Renewed! New expiry: {new_expires}", "new_expires": new_expires})


@app.route("/admin/revoke_machine", methods=["POST"])
def admin_revoke_machine():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.json or {}
    key = (data.get("key") or "").strip().upper()
    machine_id = (data.get("machine_id") or "").strip()
    if not key or not machine_id:
        return jsonify({"success": False, "message": "Key and machine_id required."}), 400
    lic = get_license_by_key(key)
    if not lic:
        return jsonify({"success": False, "message": "Key not found."}), 404
    machines = [m for m in (lic.get("machines") or []) if m.get("id") != machine_id]
    supabase.table("licenses").update({"machines": machines}).eq("key", key).execute()
    return jsonify({"success": True, "message": "Machine removed successfully."})


# ---------------------------------------------------------------------------
# Tezhisab Central Portal — Phase 1
# Email-based admin/customer login, customer master, software master and
# update metadata manager. Existing desktop app activation APIs remain intact.
# ---------------------------------------------------------------------------

@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.json or {}
    email = _normalize_email(data.get("email"))
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400
    try:
        resp = supabase.table("portal_users").select("*").eq("email", email).limit(1).execute()
        user = (resp.data or [None])[0]
    except Exception as e:
        return jsonify({"success": False, "message": "Run TEZHISAB_CENTRAL_PORTAL_SETUP.sql in Supabase SQL Editor first.", "error": str(e)}), 500

    # First-login bootstrap for the two approved administrators. Both use the
    # Render ADMIN_PASSWORD initially and can change it from Portal Settings.
    if not user and email in ADMIN_EMAILS and hmac.compare_digest(password, ADMIN_PASSWORD):
        user = {
            "email": email,
            "password_hash": _hash_password(password),
            "role": "admin",
            "display_name": email.split("@", 1)[0].replace(".", " ").title(),
            "status": "active",
            "customer_id": None,
        }
        supabase.table("portal_users").upsert(user, on_conflict="email").execute()
    if not user or (user.get("status") or "active") != "active" or not _verify_password(password, user.get("password_hash")):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401
    token = _issue_token(user)
    _write_log("portal_login", {"email": email, "role": user.get("role")}, request)
    return jsonify({"success": True, "token": token, "user": {"email": email, "role": user.get("role"), "name": user.get("display_name"), "customer_id": user.get("customer_id")}})


@app.route("/auth/me", methods=["GET"])
def auth_me():
    user = _current_user(request)
    if not user:
        return jsonify({"success": False, "message": "Login required."}), 401
    return jsonify({"success": True, "user": user})


@app.route("/auth/change-password", methods=["POST"])
def auth_change_password():
    auth = _current_user(request)
    if not auth:
        return jsonify({"success": False, "message": "Login required."}), 401
    data = request.json or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""
    if len(new_password) < 8:
        return jsonify({"success": False, "message": "New password must contain at least 8 characters."}), 400
    email = _normalize_email(auth.get("email"))
    resp = supabase.table("portal_users").select("*").eq("email", email).limit(1).execute()
    user = (resp.data or [None])[0]
    if not user or not _verify_password(old_password, user.get("password_hash")):
        return jsonify({"success": False, "message": "Current password is incorrect."}), 403
    supabase.table("portal_users").update({"password_hash": _hash_password(new_password)}).eq("email", email).execute()
    _write_log("password_changed", {"email": email}, request)
    return jsonify({"success": True, "message": "Password changed successfully."})


def _require_admin_json():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Admin login required."}), 401
    return None


@app.route("/admin/customers", methods=["GET"])
def admin_customers_list():
    denied = _require_admin_json()
    if denied: return denied
    resp = supabase.table("customers").select("*").order("created_at", desc=True).execute()
    return jsonify({"success": True, "customers": resp.data or []})


@app.route("/admin/customers", methods=["POST"])
def admin_customers_add():
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    name = (data.get("name") or "").strip()
    email = _normalize_email(data.get("email"))
    password = data.get("password") or ""
    phone = (data.get("phone") or "").strip()
    business_name = (data.get("business_name") or "").strip()
    if not name or not email or len(password) < 8:
        return jsonify({"success": False, "message": "Name, email and an initial password of at least 8 characters are required."}), 400
    try:
        customer_payload = {"name": name, "email": email, "phone": phone, "business_name": business_name, "status": "active"}
        customer_resp = supabase.table("customers").insert(customer_payload).execute()
        customer = (customer_resp.data or [None])[0]
        if not customer:
            customer = (supabase.table("customers").select("*").eq("email", email).limit(1).execute().data or [None])[0]
        user_payload = {"email": email, "password_hash": _hash_password(password), "role": "customer", "display_name": name, "customer_id": customer.get("id") if customer else None, "status": "active"}
        supabase.table("portal_users").upsert(user_payload, on_conflict="email").execute()
        _write_log("customer_created", {"email": email, "name": name}, request)
        return jsonify({"success": True, "message": "Customer account created successfully.", "customer": customer})
    except Exception as e:
        return jsonify({"success": False, "message": "Could not create customer. The email may already exist.", "error": str(e)}), 400


@app.route("/admin/customers/<int:customer_id>/reset-password", methods=["POST"])
def admin_customer_reset_password(customer_id: int):
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    new_password = data.get("password") or ""
    if len(new_password) < 8:
        return jsonify({"success": False, "message": "Password must contain at least 8 characters."}), 400
    customer = (supabase.table("customers").select("*").eq("id", customer_id).limit(1).execute().data or [None])[0]
    if not customer:
        return jsonify({"success": False, "message": "Customer not found."}), 404
    supabase.table("portal_users").update({"password_hash": _hash_password(new_password)}).eq("email", _normalize_email(customer.get("email"))).execute()
    _write_log("customer_password_reset", {"customer_id": customer_id, "email": customer.get("email")}, request)
    return jsonify({"success": True, "message": "Customer password reset successfully."})


@app.route("/admin/software", methods=["GET"])
def admin_software_list():
    denied = _require_admin_json()
    if denied: return denied
    products = fetch_products()
    try:
        channels = supabase.table("update_channels").select("*").order("product_code").execute().data or []
    except Exception:
        channels = []
    for product in products:
        product["channels"] = [c for c in channels if slug_code(c.get("product_code") or "") == product["product_code"]]
    return jsonify({"success": True, "products": products})


@app.route("/admin/software", methods=["POST"])
def admin_software_add():
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    product_name = (data.get("product_name") or "").strip()
    product_code = slug_code(data.get("product_code") or product_name)
    prefix_code = slug_code(data.get("prefix_code") or product_code)
    description = (data.get("description") or "").strip()
    default_limit = _int_or_default(data.get("default_limit"), 3)
    channel_codes = data.get("channels") or ["WINDOWS_EXE"]
    if not product_name or not product_code:
        return jsonify({"success": False, "message": "Software name and product code are required."}), 400
    if product_code in get_product_map(include_inactive=True):
        return jsonify({"success": False, "message": "Product code already exists."}), 400
    payload = {"product_name": product_name, "product_code": product_code, "prefix_code": prefix_code or product_code, "default_limit": default_limit, "status": "active", "sort_order": len(fetch_products()) + 1, "description": description, "auto_update_required": bool(data.get("auto_update_required", True)), "customer_portal_visible": bool(data.get("customer_portal_visible", True))}
    try:
        supabase.table("products").insert(payload).execute()
        for channel_code in channel_codes:
            ccode = channel_slug(channel_code) or "WINDOWSEXE"
            label = {"WINDOWSEXE":"Windows Desktop — EXE", "ANDROIDAPK":"Android Mobile — APK", "WEBAPP":"Web App"}.get(ccode, channel_code.replace("_", " ").title())
            supabase.table("update_channels").insert({"product_code": product_code, "channel_code": ccode, "channel_name": label, "platform": ccode, "status": "active"}).execute()
        _write_log("software_created", {"product_code": product_code, "product_name": product_name, "channels": channel_codes}, request)
        return jsonify({"success": True, "message": "Software created successfully.", "product": payload})
    except Exception as e:
        return jsonify({"success": False, "message": "Could not create software. Run the latest SQL setup first.", "error": str(e)}), 500


@app.route("/admin/update-channels", methods=["GET"])
def admin_update_channels_list():
    denied = _require_admin_json()
    if denied: return denied
    resp = supabase.table("update_channels").select("*").order("product_code").execute()
    product_map = get_product_map(include_inactive=True)
    channels = []
    for row in (resp.data or []):
        item = dict(row)
        product = product_map.get(normalize_product(item.get("product_code")))
        item["product_name"] = (product or {}).get("product_name") or item.get("product_code") or "Software"
        channels.append(item)
    return jsonify({"success": True, "channels": channels})


@app.route("/admin/update-channels", methods=["POST"])
def admin_update_channels_add():
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    product_code = normalize_product(data.get("product_code"))
    channel_code = channel_slug(data.get("channel_code") or "WINDOWS_EXE")
    channel_name = (data.get("channel_name") or channel_code).strip()
    if not find_product(product_code, include_inactive=True):
        return jsonify({"success": False, "message": "Create the software product first."}), 400
    payload = {"product_code": product_code, "channel_code": channel_code, "channel_name": channel_name, "platform": (data.get("platform") or channel_code), "repo_owner": (data.get("repo_owner") or "").strip(), "repo_name": (data.get("repo_name") or "").strip(), "manifest_url": (data.get("manifest_url") or "").strip(), "status": "active"}
    supabase.table("update_channels").upsert(payload, on_conflict="product_code,channel_code").execute()
    _write_log("update_channel_saved", payload, request)
    return jsonify({"success": True, "message": "Update channel saved successfully.", "channel": payload})


@app.route("/admin/versions", methods=["GET"])
def admin_versions_list():
    denied = _require_admin_json()
    if denied: return denied
    resp = supabase.table("app_versions").select("*,update_channels(product_code,channel_code,channel_name),product_editions(edition_code,edition_name,release_scope)").order("created_at", desc=True).execute()
    product_map = get_product_map(include_inactive=True)
    versions = []
    latest_groups: set[tuple[int, int]] = set()
    for row in (resp.data or []):
        item = dict(row)
        channel = dict(item.get("update_channels") or {})
        product = product_map.get(normalize_product(channel.get("product_code")))
        channel["product_name"] = (product or {}).get("product_name") or channel.get("product_code") or "Software"
        item["update_channels"] = channel
        item["edition"] = _edition_summary(dict(item.get("product_editions") or {}) or None)
        channel_id = int(item.get("channel_id") or 0)
        edition_id = int(item.get("edition_id") or 0)
        group = (channel_id, edition_id)
        item["is_latest"] = bool(channel_id and group not in latest_groups)
        if channel_id:
            latest_groups.add(group)
        versions.append(item)
    return jsonify({"success": True, "versions": versions})


@app.route("/admin/versions", methods=["POST"])
def admin_versions_add():
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    channel_id = data.get("channel_id")
    version = (data.get("version") or "").strip()
    download_url = (data.get("download_url") or "").strip()
    notes = (data.get("notes") or "").strip()
    if not channel_id or not version or not download_url:
        return jsonify({"success": False, "message": "Channel, version and download URL are required."}), 400
    edition = _fetch_edition(data.get("edition_id"))
    payload = {"channel_id": int(channel_id), "edition_id": (edition or {}).get("id"), "version": version, "download_url": download_url, "notes": notes, "mandatory": bool(data.get("mandatory")), "published": True}
    supabase.table("app_versions").insert(payload).execute()
    _write_log("app_version_published", payload, request)
    return jsonify({"success": True, "message": "External-link version published successfully.", "version": payload})


@app.route("/admin/licenses/<path:key>", methods=["DELETE"])
def admin_license_delete(key: str):
    denied = _require_admin_json()
    if denied: return denied
    clean_key = (key or "").strip().upper()
    if not clean_key:
        return jsonify({"success": False, "message": "License key required."}), 400
    lic = get_license_by_key(clean_key)
    if not lic:
        return jsonify({"success": False, "message": "License key not found."}), 404
    try:
        supabase.table("licenses").delete().eq("key", clean_key).execute()
        _write_log("license_deleted", {
            "key": clean_key,
            "product": lic.get("product_code"),
            "client_name": lic.get("client_name"),
            "client_email": lic.get("client_email"),
        }, request)
    except Exception as e:
        return jsonify({"success": False, "message": "Could not delete license.", "error": str(e)}), 500
    return jsonify({"success": True, "message": "License deleted successfully."})


@app.route("/admin/licenses/<path:key>/status", methods=["POST"])
def admin_license_status(key: str):
    denied = _require_admin_json()
    if denied: return denied
    status = ((request.json or {}).get("status") or "").lower()
    if status not in ("active", "trial", "suspended"):
        return jsonify({"success": False, "message": "Status must be active, trial or suspended."}), 400
    supabase.table("licenses").update({"status": status}).eq("key", key.strip().upper()).execute()
    _write_log("license_status_changed", {"key": key, "status": status}, request)
    return jsonify({"success": True, "message": f"License marked as {status}."})


@app.route("/admin/storage/status", methods=["GET"])
def admin_storage_status():
    denied = _require_admin_json()
    if denied: return denied
    configured = _r2_is_configured()
    return jsonify({
        "success": True,
        "configured": configured,
        "provider": "Cloudflare R2",
        "bucket": R2_BUCKET_NAME if configured else "",
        "max_upload_mb": MAX_APP_UPLOAD_MB,
        "auto_cleanup": AUTO_DELETE_OLDER_VERSIONS,
        "retention_count": APP_VERSION_RETENTION_COUNT,
        "message": "Central cloud upload is ready." if configured else "Cloudflare R2 is not configured yet. Add the Render Environment Variables first.",
    })


@app.route("/admin/storage/presign-upload", methods=["POST"])
def admin_storage_presign_upload():
    denied = _require_admin_json()
    if denied: return denied
    if not _r2_is_configured():
        return jsonify({"success": False, "message": "Cloudflare R2 is not configured. Add the required Render Environment Variables first."}), 503
    data = request.json or {}
    try:
        channel_id = int(data.get("channel_id") or 0)
        version = (data.get("version") or "").strip()
        filename = _safe_app_filename(data.get("filename") or "")
        content_type = (data.get("content_type") or "application/octet-stream").strip()
        size_bytes = int(data.get("size_bytes") or 0)
        edition_id = int(data.get("edition_id") or 0)
    except (TypeError, ValueError) as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if not channel_id or not version:
        return jsonify({"success": False, "message": "Update channel and version are required."}), 400
    if size_bytes <= 0:
        return jsonify({"success": False, "message": "Selected file is empty."}), 400
    if size_bytes > MAX_APP_UPLOAD_MB * 1024 * 1024:
        return jsonify({"success": False, "message": f"File is larger than the configured {MAX_APP_UPLOAD_MB} MB upload limit."}), 400
    channel_rows = supabase.table("update_channels").select("*").eq("id", channel_id).limit(1).execute().data or []
    if not channel_rows:
        return jsonify({"success": False, "message": "Update channel not found."}), 404
    channel = channel_rows[0]
    edition = _fetch_edition(edition_id)
    if edition and normalize_product(edition.get("product_code")) != normalize_product(channel.get("product_code")):
        return jsonify({"success": False, "message": "Selected edition does not belong to this software product."}), 400
    edition_summary = _edition_summary(edition)
    storage_key = _new_storage_key(channel, version, filename, edition_summary.get("edition_code") or "STANDARD")
    try:
        upload_url = _r2_presigned_put(storage_key, content_type)
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not prepare the secure cloud upload URL.", "error": str(exc)}), 500
    _write_log("central_upload_url_created", {"channel_id": channel_id, "version": version, "storage_key": storage_key, "size_bytes": size_bytes}, request)
    return jsonify({
        "success": True,
        "upload_url": upload_url,
        "storage_key": storage_key,
        "edition": edition_summary,
        "headers": {"Content-Type": content_type},
        "expires_in": R2_UPLOAD_URL_SECONDS,
        "message": "Secure upload URL created.",
    })


@app.route("/admin/storage/publish-upload", methods=["POST"])
def admin_storage_publish_upload():
    denied = _require_admin_json()
    if denied: return denied
    if not _r2_is_configured():
        return jsonify({"success": False, "message": "Cloudflare R2 is not configured."}), 503
    data = request.json or {}
    try:
        channel_id = int(data.get("channel_id") or 0)
        size_bytes = int(data.get("size_bytes") or 0)
        edition_id = int(data.get("edition_id") or 0)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid channel, edition or file size."}), 400
    version = (data.get("version") or "").strip()
    storage_key = (data.get("storage_key") or "").strip()
    original_filename = _safe_app_filename(data.get("original_filename") or "")
    content_type = (data.get("content_type") or "application/octet-stream").strip()
    notes = (data.get("notes") or "").strip()
    if not channel_id or not version or not storage_key.startswith("apps/"):
        return jsonify({"success": False, "message": "Channel, version and uploaded cloud file are required."}), 400
    try:
        head = _r2_client().head_object(Bucket=R2_BUCKET_NAME, Key=storage_key)
        stored_size = int(head.get("ContentLength") or 0)
        if size_bytes and stored_size != size_bytes:
            return jsonify({"success": False, "message": "Uploaded file size verification failed. Please upload again."}), 400
    except Exception as exc:
        return jsonify({"success": False, "message": "Uploaded file could not be verified in cloud storage.", "error": str(exc)}), 400
    auth = _current_user(request) or {}
    edition = _fetch_edition(edition_id)
    channel_rows = supabase.table("update_channels").select("*").eq("id", channel_id).limit(1).execute().data or []
    if not channel_rows:
        return jsonify({"success": False, "message": "Update channel not found."}), 404
    if edition and normalize_product(edition.get("product_code")) != normalize_product(channel_rows[0].get("product_code")):
        return jsonify({"success": False, "message": "Selected edition does not belong to this software product."}), 400
    payload = {
        "channel_id": channel_id,
        "edition_id": (edition or {}).get("id"),
        "version": version,
        "download_url": f"r2://{R2_BUCKET_NAME}/{storage_key}",
        "notes": notes,
        "mandatory": bool(data.get("mandatory")),
        "published": True,
        "storage_provider": "cloudflare_r2",
        "storage_key": storage_key,
        "original_filename": original_filename,
        "content_type": content_type,
        "size_bytes": stored_size,
        "uploaded_by": auth.get("email") or "admin",
    }
    try:
        created = supabase.table("app_versions").insert(payload).execute().data or []
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not publish this upload. Run the latest Phase 3 SQL file first, or use a different version number.", "error": str(exc)}), 500
    cleanup = {"removed": [], "failed": [], "keep_count": APP_VERSION_RETENTION_COUNT}
    if AUTO_DELETE_OLDER_VERSIONS:
        cleanup = _cleanup_old_cloud_versions(channel_id, APP_VERSION_RETENTION_COUNT, (edition or {}).get("id"))
    _write_log("central_app_version_uploaded", {**payload, "cleanup": cleanup}, request)
    removed_count = len(cleanup.get("removed") or [])
    message = "App uploaded and published successfully."
    if removed_count:
        message += f" {removed_count} older cloud version(s) were removed automatically."
    return jsonify({"success": True, "message": message, "version": (created or [payload])[0], "cleanup": cleanup})


@app.route("/admin/storage/cleanup", methods=["POST"])
def admin_storage_cleanup():
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    try:
        channel_id = int(data.get("channel_id") or 0)
        keep_count = max(1, int(data.get("keep_count") or APP_VERSION_RETENTION_COUNT))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid cleanup settings."}), 400
    result = _cleanup_old_cloud_versions(channel_id, keep_count) if channel_id else _cleanup_all_cloud_versions(keep_count)
    _write_log("cloud_storage_cleanup", result, request)
    removed_count = len(result.get("removed") or []) if channel_id else int(result.get("removed_count") or 0)
    failed_count = len(result.get("failed") or []) if channel_id else int(result.get("failed_count") or 0)
    return jsonify({
        "success": True,
        "message": f"Storage cleanup complete. Removed {removed_count} older cloud version(s)." + (f" {failed_count} file(s) could not be removed; retry later." if failed_count else ""),
        "cleanup": result,
    })


@app.route("/admin/versions/<int:version_id>/rollback", methods=["POST"])
def admin_version_rollback(version_id: int):
    denied = _require_admin_json()
    if denied: return denied
    rows = supabase.table("app_versions").select("*").eq("id", version_id).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Published version not found."}), 404
    version = rows[0]
    storage_key = (version.get("storage_key") or "").strip()
    if storage_key:
        if not _r2_is_configured():
            return jsonify({"success": False, "message": "Cloud storage is not configured."}), 503
        try:
            _r2_client().head_object(Bucket=R2_BUCKET_NAME, Key=storage_key)
        except Exception as exc:
            return jsonify({"success": False, "message": "This older installer file is no longer available in cloud storage.", "error": str(exc)}), 404
    elif not (version.get("download_url") or "").strip().lower().startswith(("https://", "http://")):
        return jsonify({"success": False, "message": "This version does not have a valid download file."}), 400
    now_value = datetime.utcnow().isoformat() + "Z"
    supabase.table("app_versions").update({"published": True, "created_at": now_value}).eq("id", version_id).execute()
    _write_log("app_version_rolled_back", {"version_id": version_id, "version": version.get("version"), "channel_id": version.get("channel_id")}, request)
    return jsonify({"success": True, "message": f"Rollback complete. Version {version.get('version')} is now the latest published version."})


@app.route("/admin/versions/<int:version_id>", methods=["DELETE"])
def admin_version_delete(version_id: int):
    denied = _require_admin_json()
    if denied: return denied
    rows = supabase.table("app_versions").select("*").eq("id", version_id).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Published version not found."}), 404
    version = rows[0]
    storage_key = (version.get("storage_key") or "").strip()
    ok, error = _delete_cloud_version(version)
    if not ok:
        return jsonify({"success": False, "message": "Could not delete the published version from cloud storage.", "error": error}), 500
    _write_log("app_version_deleted", {"version_id": version_id, "storage_key": storage_key}, request)
    return jsonify({"success": True, "message": "Published version deleted successfully."})


@app.route("/customer/dashboard", methods=["GET"])
def customer_dashboard():
    auth = _current_user(request)
    if not auth or auth.get("role") not in ("customer", "admin"):
        return jsonify({"success": False, "message": "Customer login required."}), 401
    email = _normalize_email(auth.get("email"))
    if auth.get("role") == "admin" and request.args.get("email"):
        email = _normalize_email(request.args.get("email"))
    licenses_resp = supabase.table("licenses").select("*").eq("client_email", email).order("activated_on", desc=True).execute()
    licenses = [enrich_license(row) for row in (licenses_resp.data or [])]
    channels = supabase.table("update_channels").select("*").eq("status", "active").execute().data or []
    products = []
    for lic in licenses:
        product_channels = []
        for channel in channels:
            if slug_code(channel.get("product_code") or "") == lic.get("product_code"):
                item = dict(channel)
                _, latest = _latest_channel_version(lic.get("product_code"), channel.get("channel_code"), lic.get("edition_id"))
                item["latest_version"] = _version_response(latest, include_presigned_download=False)
                product_channels.append(item)
        products.append({"license": lic, "edition": _edition_for_license(lic), "channels": product_channels})
    return jsonify({"success": True, "email": email, "products": products})


@app.route("/customer/download/<int:version_id>", methods=["GET"])
def customer_download(version_id: int):
    auth = _portal_user_from_request(request)
    if not auth or auth.get("role") not in ("customer", "admin"):
        return jsonify({"success": False, "message": "Customer login required."}), 401
    rows = supabase.table("app_versions").select("*,update_channels(product_code,channel_code)").eq("id", version_id).eq("published", True).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Published app version not found."}), 404
    version = rows[0]
    channel = dict(version.get("update_channels") or {})
    product_code = normalize_product(channel.get("product_code"))
    lic = None
    if auth.get("role") != "admin":
        lic = _active_license_for_email_product_edition(auth.get("email") or "", product_code, version.get("edition_id"))
        if not lic:
            return jsonify({"success": False, "message": "This software is not assigned to your active customer account."}), 403
        if int(version.get("edition_id") or 0) != int(lic.get("edition_id") or 0):
            return jsonify({"success": False, "message": "This download belongs to a different customer edition."}), 403
    storage_key = (version.get("storage_key") or "").strip()
    if storage_key:
        if not _r2_is_configured():
            return jsonify({"success": False, "message": "Cloud download is temporarily unavailable. Please contact Tezhisab support."}), 503
        url = _r2_presigned_get(storage_key)
    else:
        url = (version.get("download_url") or "").strip()
        if not url.lower().startswith(("https://", "http://")):
            return jsonify({"success": False, "message": "Download link is not configured."}), 404
    _write_log("customer_app_download", {"version_id": version_id, "product_code": product_code, "edition_id": version.get("edition_id"), "email": auth.get("email")}, request)
    return redirect(url, code=302)


def _latest_channel_version(product_code: str, channel_code: str, edition_id: Any = None):
    product_code = normalize_product(product_code)
    channel_code = channel_slug(channel_code)
    channel_rows = supabase.table("update_channels").select("*").eq("product_code", product_code).eq("channel_code", channel_code).limit(1).execute().data or []
    channel = (channel_rows or [None])[0]
    if not channel:
        possible = supabase.table("update_channels").select("*").eq("product_code", product_code).execute().data or []
        channel = next((row for row in possible if channel_slug(row.get("channel_code")) == channel_code), None)
    if not channel:
        return None, None
    query = supabase.table("app_versions").select("*").eq("channel_id", channel.get("id")).eq("published", True)
    if edition_id:
        query = query.eq("edition_id", int(edition_id))
    else:
        query = query.is_("edition_id", "null")
    versions = query.order("created_at", desc=True).limit(1).execute().data or []
    return channel, (versions or [None])[0]

@app.route("/updates/check", methods=["GET"])
def updates_check():
    """Legacy metadata endpoint. Existing GitHub-based apps remain compatible.

    For central R2 uploads, installed apps should move to /api/v2/updates/check so
    a valid license key can receive a temporary secure download URL.
    """
    product_code = normalize_product(request.args.get("product"))
    channel_code = channel_slug(request.args.get("channel") or "WINDOWS_EXE")
    current_version = (request.args.get("current_version") or "").strip()
    channel, latest = _latest_channel_version(product_code, channel_code)
    if not channel:
        return jsonify({"success": False, "message": "Update channel not configured."}), 404
    public_latest = _version_response(latest, include_presigned_download=False)
    return jsonify({"success": True, "product": product_code, "channel": channel_code, "current_version": current_version, "latest": public_latest, "update_available": bool(latest and latest.get("version") != current_version)})


@app.route("/api/v2/updates/check", methods=["GET", "POST"])
def secure_updates_check():
    """Secure updater endpoint for future app builds connected to Tezhisab Portal."""
    data = request.get_json(silent=True) or request.args
    key = (data.get("license_key") or data.get("key") or "").strip().upper()
    product_code = normalize_product(data.get("product"))
    channel_code = channel_slug(data.get("channel") or "WINDOWS_EXE")
    current_version = (data.get("current_version") or "").strip()
    machine_id = (data.get("machine_id") or "").strip()
    lic = get_license_by_key(key)
    if not lic:
        return jsonify({"success": False, "message": "License key not found."}), 404
    if lic.get("product_code") != product_code:
        return jsonify({"success": False, "message": "License key is not valid for this software."}), 403
    if lic.get("status") == "suspended" or lic.get("days_left", -1) < 0:
        return jsonify({"success": False, "message": "License is inactive or expired."}), 403
    machines = lic.get("machines") or []
    if machine_id and machines and machine_id not in {m.get("id") for m in machines}:
        return jsonify({"success": False, "message": "This computer is not activated for the license."}), 403
    edition = _edition_for_license(lic)
    requested_edition = _edition_code(data.get("edition_code") or data.get("variant") or edition.get("edition_code"))
    if requested_edition not in {"STANDARD", _edition_code(edition.get("edition_code"))}:
        return jsonify({"success": False, "message": "This license is assigned to a different software edition."}), 403
    channel, latest = _latest_channel_version(product_code, channel_code, lic.get("edition_id"))
    if not channel:
        return jsonify({"success": False, "message": "Update channel not configured."}), 404
    secure_latest = _version_response(latest, include_presigned_download=True)
    return jsonify({
        "success": True,
        "product": product_code,
        "channel": channel_code,
        "edition": edition,
        "current_version": current_version,
        "latest": secure_latest,
        "update_available": bool(latest and latest.get("version") != current_version),
        "license_status": lic.get("status"),
        "license_expires_on": lic.get("expires_on"),
    })



# ---------------------------------------------------------------------------
# Tezhisab Central Platform — Phase 3
# Customer self-registration, requirement workflow, custom product editions,
# customer-specific releases and tutorial video manager.
# ---------------------------------------------------------------------------

def _safe_customer_public(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row.get(k) for k in ("id", "name", "email", "phone", "business_name", "status", "created_at", "approved_at", "approved_by", "rejection_reason")}


def _customer_by_email(email: str) -> dict[str, Any] | None:
    rows = supabase.table("customers").select("*").eq("email", _normalize_email(email)).limit(1).execute().data or []
    return rows[0] if rows else None


def _customer_for_auth(auth: dict[str, Any] | None) -> dict[str, Any] | None:
    if not auth:
        return None
    if auth.get("customer_id"):
        rows = supabase.table("customers").select("*").eq("id", int(auth.get("customer_id"))).limit(1).execute().data or []
        if rows:
            return rows[0]
    return _customer_by_email(auth.get("email") or "")


def _require_customer_auth() -> tuple[dict[str, Any] | None, Any]:
    auth = _current_user(request)
    if not auth or auth.get("role") not in ("customer", "admin"):
        return None, (jsonify({"success": False, "message": "Customer login required."}), 401)
    return auth, None


def _bank_import_launch_ticket_hash(ticket: str) -> str:
    return hashlib.sha256((ticket or "").encode("utf-8")).hexdigest()


def _bank_import_launch_url(ticket: str) -> str:
    base = BANK_IMPORT_WEB_APP_URL or "http://localhost:7357"
    query = urllib_parse.urlencode({
        "ticket": ticket,
        # Customers entering from the Central Portal should land directly on
        # the live wallet / trial-access page. All other workspace tabs remain
        # available from the Bank Import Pro top navigation.
        "start": "wallet",
        # Keep test and production deployments isolated automatically. The
        # Flutter app exchanges the one-time ticket with the same API host that
        # issued it.
        "api": request.url_root.rstrip("/"),
    })
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{query}"


def _safe_bank_import_launch_ticket_cleanup() -> None:
    try:
        supabase.table("bank_import_launch_tickets").delete().lt("expires_at", datetime.utcnow().isoformat() + "Z").execute()
    except Exception:
        # Cleanup is best-effort. Ticket expiry is still enforced by the atomic
        # consume RPC.
        pass


@app.route("/customer/bank-import/launch-ticket", methods=["POST"])
def customer_bank_import_launch_ticket():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    if (auth or {}).get("role") != "customer":
        return jsonify({"success": False, "message": "Use an approved customer login to open Bank Import Pro."}), 403
    customer = _customer_for_auth(auth)
    if not customer:
        return jsonify({"success": False, "message": "Approved customer profile was not found."}), 404

    raw_ticket = secrets.token_urlsafe(36)
    expires_at = datetime.utcnow() + timedelta(seconds=BANK_IMPORT_LAUNCH_TICKET_SECONDS)
    try:
        _safe_bank_import_launch_ticket_cleanup()
        supabase.table("bank_import_launch_tickets").insert({
            "ticket_hash": _bank_import_launch_ticket_hash(raw_ticket),
            "customer_id": int(customer.get("id")),
            "issued_to_email": _normalize_email(auth.get("email")),
            "expires_at": expires_at.isoformat() + "Z",
        }).execute()
    except Exception as exc:
        return jsonify({
            "success": False,
            "message": "Bank Import launch setup is not ready. Run the latest V17 SQL in Supabase SQL Editor.",
            "error": str(exc),
        }), 500

    _write_log("bank_import_web_launch_ticket_issued", {"customer_id": customer.get("id")}, request)
    return jsonify({
        "success": True,
        "launch_url": _bank_import_launch_url(raw_ticket),
        "expires_in": BANK_IMPORT_LAUNCH_TICKET_SECONDS,
    })


@app.route("/customer/bank-import/exchange-launch-ticket", methods=["POST"])
def customer_bank_import_exchange_launch_ticket():
    data = request.get_json(silent=True) or {}
    raw_ticket = (data.get("ticket") or "").strip()
    if not raw_ticket or len(raw_ticket) > 300:
        return jsonify({"success": False, "message": "Bank Import launch link is invalid or has expired. Open it again from the Central Portal."}), 400
    try:
        consumed = supabase.rpc("consume_bank_import_launch_ticket", {
            "p_ticket_hash": _bank_import_launch_ticket_hash(raw_ticket),
        }).execute().data or []
    except Exception as exc:
        return jsonify({
            "success": False,
            "message": "Bank Import launch setup is not ready. Run the latest V17 SQL in Supabase SQL Editor.",
            "error": str(exc),
        }), 500
    if not consumed:
        return jsonify({"success": False, "message": "Bank Import launch link is invalid, expired or already used. Open it again from the Central Portal."}), 401

    ticket_row = consumed[0]
    customer_id = int(ticket_row.get("customer_id") or 0)
    email = _normalize_email(ticket_row.get("issued_to_email"))
    users = supabase.table("portal_users").select("*").eq("email", email).eq("status", "active").limit(1).execute().data or []
    portal_user = users[0] if users else None
    if not portal_user or (portal_user.get("role") or "").lower() != "customer":
        return jsonify({"success": False, "message": "Approved customer login is no longer active."}), 403
    customer = _customer_for_auth({"customer_id": customer_id, "email": email})
    if not customer or int(customer.get("id") or 0) != customer_id:
        return jsonify({"success": False, "message": "Approved customer profile was not found."}), 404

    portal_user = dict(portal_user)
    portal_user["customer_id"] = customer_id
    token = _issue_token(portal_user)
    _write_log("bank_import_web_launch_ticket_consumed", {"customer_id": customer_id, "email": email})
    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "email": email,
            "role": "customer",
            "name": portal_user.get("display_name") or customer.get("name") or email,
            "customer_id": customer_id,
        },
    })


def _issue_requirement_upload_ticket(storage_key: str, email: str) -> str:
    payload = {"storage_key": storage_key, "email": _normalize_email(email), "exp": int(time.time()) + 1800}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def _read_requirement_upload_ticket(ticket: str | None, email: str) -> dict[str, Any] | None:
    try:
        body, sig = (ticket or "").split(".", 1)
        expected = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64decode(body).decode())
        if int(payload.get("exp") or 0) < int(time.time()):
            return None
        if _normalize_email(payload.get("email")) != _normalize_email(email):
            return None
        if not (payload.get("storage_key") or "").startswith("requirements/"):
            return None
        return payload
    except Exception:
        return None


def _attachment_ticket(data: dict[str, Any], email: str) -> tuple[dict[str, Any] | None, Any]:
    if not _r2_is_configured():
        return None, (jsonify({"success": False, "message": "Attachment storage is not configured yet. Submit the written requirement without an attachment, or contact Tezhisab support."}), 503)
    try:
        filename = _safe_requirement_filename(data.get("filename") or "")
        content_type = (data.get("content_type") or "application/octet-stream").strip()
        size_bytes = int(data.get("size_bytes") or 0)
    except (TypeError, ValueError) as exc:
        return None, (jsonify({"success": False, "message": str(exc)}), 400)
    if size_bytes <= 0:
        return None, (jsonify({"success": False, "message": "Selected attachment is empty."}), 400)
    if size_bytes > MAX_REQUIREMENT_UPLOAD_MB * 1024 * 1024:
        return None, (jsonify({"success": False, "message": f"Attachment is larger than the {MAX_REQUIREMENT_UPLOAD_MB} MB limit."}), 400)
    storage_key = _new_requirement_storage_key(email, filename)
    upload_url = _r2_presigned_put(storage_key, content_type)
    return {"success": True, "upload_url": upload_url, "storage_key": storage_key, "attachment_ticket": _issue_requirement_upload_ticket(storage_key, email), "headers": {"Content-Type": content_type}, "expires_in": R2_UPLOAD_URL_SECONDS}, None


def _requirement_payload(data: dict[str, Any], customer: dict[str, Any] | None, submitted_by: str, request_type: str = "software_requirement") -> dict[str, Any]:
    return {
        "customer_id": (customer or {}).get("id"),
        "submitted_by_email": _normalize_email(submitted_by),
        "contact_name": (data.get("contact_name") or (customer or {}).get("name") or "").strip(),
        "business_name": (data.get("business_name") or (customer or {}).get("business_name") or "").strip(),
        "phone": (data.get("phone") or (customer or {}).get("phone") or "").strip(),
        "product_code": normalize_product(data.get("product_code")) if data.get("product_code") else "",
        "request_type": request_type,
        "title": (data.get("title") or "Software requirement").strip(),
        "details": (data.get("details") or "").strip(),
        "status": "pending",
        "attachment_storage_key": (data.get("attachment_storage_key") or "").strip() if (data.get("attachment_storage_key") or "").strip().startswith("requirements/") else "",
        "attachment_filename": _safe_requirement_filename(data.get("attachment_filename")) if data.get("attachment_filename") else "",
        "attachment_content_type": (data.get("attachment_content_type") or "").strip(),
        "attachment_size_bytes": int(data.get("attachment_size_bytes") or 0),
    }


def _safe_requirement(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["has_attachment"] = bool((item.get("attachment_storage_key") or "").strip())
    item.pop("attachment_storage_key", None)
    return item


@app.route("/public/config", methods=["GET"])
def public_config():
    return jsonify({
        "success": True,
        "brand": BRAND_NAME,
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "turnstile_enabled": bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY),
        "max_requirement_upload_mb": MAX_REQUIREMENT_UPLOAD_MB,
        "max_recharge_screenshot_mb": MAX_RECHARGE_SCREENSHOT_MB,
    })


@app.route("/public/products", methods=["GET"])
def public_products():
    products = [p for p in fetch_products() if p.get("status") == "active" and p.get("customer_portal_visible", True)]
    return jsonify({"success": True, "products": products})


@app.route("/auth/register", methods=["POST"])
def auth_register():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    email = _normalize_email(data.get("email"))
    upload_key = (data.get("attachment_storage_key") or "").strip()
    upload_ticket = _read_requirement_upload_ticket(data.get("attachment_ticket"), email) if upload_key else None
    if upload_key and (not upload_ticket or upload_ticket.get("storage_key") != upload_key):
        return jsonify({"success": False, "message": "Attachment upload authorization expired. Please select and upload the attachment again."}), 400
    if not upload_key:
        ok, message = _verify_turnstile(data.get("turnstile_token"), request.remote_addr)
        if not ok:
            return jsonify({"success": False, "message": message}), 400
    password = data.get("password") or ""
    phone = (data.get("phone") or "").strip()
    business_name = (data.get("business_name") or "").strip()
    details = (data.get("details") or "").strip()
    if not name or not email or len(password) < 8:
        return jsonify({"success": False, "message": "Name, email and password of at least 8 characters are required."}), 400
    if not details:
        return jsonify({"success": False, "message": "Please describe your software requirement."}), 400
    try:
        if _customer_by_email(email) or (supabase.table("portal_users").select("email").eq("email", email).limit(1).execute().data or []):
            return jsonify({"success": False, "message": "An account already exists for this email. Please login or contact Tezhisab support."}), 409
        customer_payload = {"name": name, "email": email, "phone": phone, "business_name": business_name, "status": "pending"}
        created = supabase.table("customers").insert(customer_payload).execute().data or []
        customer = created[0] if created else _customer_by_email(email)
        supabase.table("portal_users").insert({"email": email, "password_hash": _hash_password(password), "role": "customer", "display_name": name, "customer_id": (customer or {}).get("id"), "status": "pending"}).execute()
        requirement = _requirement_payload(data, customer, email, "new_customer_registration")
        requirement["title"] = (data.get("title") or "New customer software request").strip()
        supabase.table("customer_requirements").insert(requirement).execute()
        _write_log("customer_self_registered", {"email": email, "customer_id": (customer or {}).get("id")}, request)
        return jsonify({"success": True, "message": "Registration submitted successfully. Tezhisab will review your requirement and approve your customer login."})
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not submit registration. Run the latest Phase 3 SQL in Supabase SQL Editor first.", "error": str(exc)}), 500


@app.route("/public/requirements/presign-upload", methods=["POST"])
def public_requirement_presign_upload():
    data = request.json or {}
    ok, message = _verify_turnstile(data.get("turnstile_token"), request.remote_addr)
    if not ok:
        return jsonify({"success": False, "message": message}), 400
    email = _normalize_email(data.get("email"))
    if not email:
        return jsonify({"success": False, "message": "Enter your email before uploading an attachment."}), 400
    ticket, denied = _attachment_ticket(data, email)
    return denied or jsonify(ticket)


@app.route("/customer/requirements/presign-upload", methods=["POST"])
def customer_requirement_presign_upload():
    auth, denied = _require_customer_auth()
    if denied: return denied
    ticket, error = _attachment_ticket(request.json or {}, auth.get("email") or "customer")
    return error or jsonify(ticket)


@app.route("/customer/requirements", methods=["GET", "POST"])
def customer_requirements():
    auth, denied = _require_customer_auth()
    if denied: return denied
    customer = _customer_for_auth(auth)
    if request.method == "GET":
        query = supabase.table("customer_requirements").select("*")
        if customer and customer.get("id"):
            query = query.eq("customer_id", customer.get("id"))
        else:
            query = query.eq("submitted_by_email", _normalize_email(auth.get("email")))
        rows = query.order("created_at", desc=True).execute().data or []
        return jsonify({"success": True, "requirements": [_safe_requirement(row) for row in rows]})
    data = request.json or {}
    if not (data.get("details") or "").strip():
        return jsonify({"success": False, "message": "Requirement details are required."}), 400
    payload = _requirement_payload(data, customer, auth.get("email") or "")
    created = supabase.table("customer_requirements").insert(payload).execute().data or []
    _write_log("customer_requirement_submitted", {"customer_id": (customer or {}).get("id"), "product_code": payload.get("product_code")}, request)
    return jsonify({"success": True, "message": "Requirement submitted successfully.", "requirement": _safe_requirement((created or [payload])[0])})


@app.route("/admin/registration-requests", methods=["GET"])
def admin_registration_requests():
    denied = _require_admin_json()
    if denied: return denied
    rows = supabase.table("customers").select("*").eq("status", "pending").order("created_at", desc=True).execute().data or []
    return jsonify({"success": True, "requests": [_safe_customer_public(row) for row in rows]})


@app.route("/admin/registration-requests/<int:customer_id>/status", methods=["POST"])
def admin_registration_request_status(customer_id: int):
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    status = (data.get("status") or "").strip().lower()
    if status not in {"active", "rejected"}:
        return jsonify({"success": False, "message": "Status must be active or rejected."}), 400
    rows = supabase.table("customers").select("*").eq("id", customer_id).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Customer request not found."}), 404
    customer = rows[0]
    auth = _current_user(request) or {}
    payload = {"status": status, "approved_at": datetime.utcnow().isoformat()+"Z" if status == "active" else None, "approved_by": auth.get("email") or "admin", "rejection_reason": (data.get("reason") or "").strip()}
    supabase.table("customers").update(payload).eq("id", customer_id).execute()
    supabase.table("portal_users").update({"status": status}).eq("email", _normalize_email(customer.get("email"))).execute()
    _write_log("customer_registration_status_changed", {"customer_id": customer_id, "status": status}, request)
    return jsonify({"success": True, "message": "Customer login approved successfully." if status == "active" else "Customer request rejected."})


@app.route("/admin/requirements", methods=["GET"])
def admin_requirements_list():
    denied = _require_admin_json()
    if denied: return denied
    rows = supabase.table("customer_requirements").select("*").order("created_at", desc=True).execute().data or []
    return jsonify({"success": True, "requirements": [_safe_requirement(row) for row in rows]})


@app.route("/admin/requirements/<int:requirement_id>/status", methods=["POST"])
def admin_requirement_status(requirement_id: int):
    denied = _require_admin_json()
    if denied: return denied
    data = request.json or {}
    status = (data.get("status") or "").strip().lower()
    if status not in {"pending", "reviewing", "approved", "completed", "rejected"}:
        return jsonify({"success": False, "message": "Invalid requirement status."}), 400
    auth = _current_user(request) or {}
    payload = {"status": status, "admin_notes": (data.get("admin_notes") or "").strip(), "reviewed_by": auth.get("email") or "admin", "reviewed_at": datetime.utcnow().isoformat()+"Z"}
    supabase.table("customer_requirements").update(payload).eq("id", requirement_id).execute()
    _write_log("customer_requirement_status_changed", {"requirement_id": requirement_id, "status": status}, request)
    return jsonify({"success": True, "message": f"Requirement marked as {status}."})


def _requirement_attachment_redirect(requirement_id: int, auth: dict[str, Any]):
    rows = supabase.table("customer_requirements").select("*").eq("id", requirement_id).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Attachment not found."}), 404
    item = rows[0]
    if auth.get("role") != "admin":
        customer = _customer_for_auth(auth)
        if not customer or int(item.get("customer_id") or 0) != int(customer.get("id") or 0):
            return jsonify({"success": False, "message": "This attachment does not belong to your account."}), 403
    key = (item.get("attachment_storage_key") or "").strip()
    if not key or not _r2_is_configured():
        return jsonify({"success": False, "message": "Attachment is unavailable."}), 404
    return redirect(_r2_presigned_get(key), code=302)


@app.route("/admin/requirements/<int:requirement_id>/attachment", methods=["GET"])
def admin_requirement_attachment(requirement_id: int):
    auth = _portal_user_from_request(request)
    if not auth or auth.get("role") != "admin":
        return jsonify({"success": False, "message": "Admin login required."}), 401
    return _requirement_attachment_redirect(requirement_id, auth)


@app.route("/customer/requirements/<int:requirement_id>/attachment", methods=["GET"])
def customer_requirement_attachment(requirement_id: int):
    auth = _portal_user_from_request(request)
    if not auth or auth.get("role") not in ("customer", "admin"):
        return jsonify({"success": False, "message": "Customer login required."}), 401
    return _requirement_attachment_redirect(requirement_id, auth)


@app.route("/admin/editions", methods=["GET", "POST"])
def admin_editions():
    denied = _require_admin_json()
    if denied: return denied
    if request.method == "GET":
        rows = supabase.table("product_editions").select("*,customers(name,email,business_name)").order("created_at", desc=True).execute().data or []
        return jsonify({"success": True, "editions": rows})
    data = request.json or {}
    product_code = normalize_product(data.get("product_code"))
    edition_name = (data.get("edition_name") or "").strip()
    edition_code = _edition_code(data.get("edition_code") or edition_name)
    release_scope = (data.get("release_scope") or "customer_specific").strip()
    customer_id = int(data.get("customer_id") or 0) or None
    if not find_product(product_code, include_inactive=True) or not edition_name:
        return jsonify({"success": False, "message": "Software product and edition name are required."}), 400
    if release_scope not in {"customer_specific", "selected_customers"}:
        return jsonify({"success": False, "message": "Edition scope must be customer_specific or selected_customers."}), 400
    if release_scope == "customer_specific" and not customer_id:
        return jsonify({"success": False, "message": "Select the customer for this custom edition."}), 400
    payload = {"product_code": product_code, "edition_code": edition_code, "edition_name": edition_name, "release_scope": release_scope, "customer_id": customer_id, "status": "active", "notes": (data.get("notes") or "").strip()}
    created = supabase.table("product_editions").insert(payload).execute().data or []
    edition = (created or [payload])[0]
    if customer_id and edition.get("id"):
        supabase.table("edition_customers").upsert({"edition_id": edition.get("id"), "customer_id": customer_id}, on_conflict="edition_id,customer_id").execute()
    _write_log("custom_edition_created", payload, request)
    return jsonify({"success": True, "message": "Customer-specific edition created successfully.", "edition": edition})


@app.route("/admin/editions/<int:edition_id>/status", methods=["POST"])
def admin_edition_status(edition_id: int):
    denied = _require_admin_json()
    if denied: return denied
    status = ((request.json or {}).get("status") or "").strip().lower()
    if status not in {"active", "inactive"}:
        return jsonify({"success": False, "message": "Status must be active or inactive."}), 400
    supabase.table("product_editions").update({"status": status}).eq("id", edition_id).execute()
    return jsonify({"success": True, "message": f"Edition marked as {status}."})


def _tutorial_rows(public_only: bool = False, customer_id: int | None = None):
    rows = supabase.table("tutorial_videos").select("*").eq("status", "active").order("sort_order").execute().data or []
    result = []
    for row in rows:
        visibility = (row.get("visibility") or "public").lower()
        if public_only and visibility != "public":
            continue
        if not public_only and visibility == "selected_customer" and int(row.get("customer_id") or 0) != int(customer_id or 0):
            continue
        result.append(row)
    return result


@app.route("/public/tutorials", methods=["GET"])
def public_tutorials():
    return jsonify({"success": True, "tutorials": _tutorial_rows(public_only=True)})


@app.route("/customer/tutorials", methods=["GET"])
def customer_tutorials():
    auth, denied = _require_customer_auth()
    if denied: return denied
    customer = _customer_for_auth(auth)
    return jsonify({"success": True, "tutorials": _tutorial_rows(public_only=False, customer_id=(customer or {}).get("id"))})


@app.route("/admin/tutorials", methods=["GET", "POST"])
def admin_tutorials():
    denied = _require_admin_json()
    if denied: return denied
    if request.method == "GET":
        rows = supabase.table("tutorial_videos").select("*,customers(name,email)").order("sort_order").execute().data or []
        return jsonify({"success": True, "tutorials": rows})
    data = request.json or {}
    title = (data.get("title") or "").strip()
    video_url = (data.get("video_url") or "").strip()
    visibility = (data.get("visibility") or "public").strip().lower()
    customer_id = int(data.get("customer_id") or 0) or None
    if not title or not video_url.lower().startswith(("https://", "http://")):
        return jsonify({"success": False, "message": "Tutorial title and valid video URL are required."}), 400
    if visibility not in {"public", "customer_only", "selected_customer"}:
        return jsonify({"success": False, "message": "Invalid tutorial visibility."}), 400
    if visibility == "selected_customer" and not customer_id:
        return jsonify({"success": False, "message": "Select a customer for a customer-specific tutorial."}), 400
    payload = {"title": title, "product_code": normalize_product(data.get("product_code")) if data.get("product_code") else "", "category": (data.get("category") or "Tutorial").strip(), "video_url": video_url, "thumbnail_url": (data.get("thumbnail_url") or "").strip(), "visibility": visibility, "customer_id": customer_id, "sort_order": int(data.get("sort_order") or 100), "status": "active", "description": (data.get("description") or "").strip()}
    created = supabase.table("tutorial_videos").insert(payload).execute().data or []
    _write_log("tutorial_video_created", payload, request)
    return jsonify({"success": True, "message": "Tutorial video added successfully.", "tutorial": (created or [payload])[0]})


@app.route("/admin/tutorials/<int:tutorial_id>", methods=["DELETE"])
def admin_tutorial_delete(tutorial_id: int):
    denied = _require_admin_json()
    if denied: return denied
    supabase.table("tutorial_videos").delete().eq("id", tutorial_id).execute()
    return jsonify({"success": True, "message": "Tutorial video deleted successfully."})



# ---------------------------------------------------------------------------
# Tezhisab Central Platform — Phase 4
# Bank Import Pro manual recharge wallet. Only commercial wallet metadata is
# stored in cloud. Tally ledgers, narration groups, mappings and accounting
# entries remain local to the customer's connector PC.
# ---------------------------------------------------------------------------

def _wallet_for_customer(customer_id: int, create_if_missing: bool = True) -> dict[str, Any] | None:
    rows = supabase.table("bank_import_wallets").select("*").eq("customer_id", int(customer_id)).limit(1).execute().data or []
    if rows:
        return rows[0]
    if not create_if_missing:
        return None
    payload = {
        "customer_id": int(customer_id),
        "page_balance": 0,
        "reserved_pages": 0,
        "total_pages_credited": 0,
        "total_pages_used": 0,
        "status": "active",
    }
    created = supabase.table("bank_import_wallets").insert(payload).execute().data or []
    return (created or [payload])[0]


def _safe_wallet(row: dict[str, Any] | None) -> dict[str, Any]:
    item = dict(row or {})
    item["page_balance"] = int(item.get("page_balance") or 0)
    item["reserved_pages"] = max(0, int(item.get("reserved_pages") or 0))
    item["available_pages"] = max(0, item["page_balance"] - item["reserved_pages"])
    item["total_pages_credited"] = int(item.get("total_pages_credited") or 0)
    item["total_pages_used"] = int(item.get("total_pages_used") or 0)
    item["status"] = (item.get("status") or "active").strip().lower()
    return item


def _rpc_first(value: Any) -> dict[str, Any]:
    """Return the first Supabase RPC row without trusting the wire shape."""
    rows = value or []
    if isinstance(rows, dict):
        return dict(rows)
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return dict(rows[0])
    return {}


def _release_bank_import_reservation(reservation_id: int | None, reason: str) -> tuple[bool, str]:
    """Release a held page reservation. This is intentionally idempotent."""
    try:
        numeric_id = int(reservation_id or 0)
    except Exception:
        numeric_id = 0
    if numeric_id <= 0:
        return False, ""
    try:
        result = supabase.rpc(
            "release_bank_import_pages",
            {
                "p_reservation_id": numeric_id,
                "p_reason": (reason or "Processing did not complete.")[:500],
                "p_created_by": "processing-api",
            },
        ).execute().data
        released = _rpc_first(result)
        return bool(released.get("released") or released.get("was_released")), ""
    except Exception as exc:
        return False, str(exc)


def _safe_recharge_plan(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["pages"] = int(item.get("pages") or 0)
    item["amount"] = float(item.get("amount") or 0)
    item["validity_days"] = int(item.get("validity_days") or 365)
    item["sort_order"] = int(item.get("sort_order") or 100)
    item["status"] = (item.get("status") or "inactive").strip().lower()
    return item


def _safe_recharge_request(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["requested_pages"] = int(item.get("requested_pages") or 0)
    item["amount"] = float(item.get("amount") or 0)
    item["validity_days"] = int(item.get("validity_days") or 0)
    item["proof_available"] = bool((item.get("proof_storage_key") or "").strip())
    item.pop("proof_storage_key", None)
    return item


def _bank_import_payment_settings() -> dict[str, Any]:
    rows = supabase.table("bank_import_payment_settings").select("*").eq("id", 1).limit(1).execute().data or []
    if rows:
        return dict(rows[0])
    payload = {
        "id": 1,
        "receiver_name": "",
        "upi_id": "",
        "payment_note": "Payment details will be updated by Tezhisab support.",
        "qr_image_url": "",
    }
    try:
        created = supabase.table("bank_import_payment_settings").insert(payload).execute().data or []
        return dict((created or [payload])[0])
    except Exception:
        return payload


def _active_bank_import_plans() -> list[dict[str, Any]]:
    rows = (
        supabase.table("bank_import_recharge_plans")
        .select("*")
        .eq("status", "active")
        .order("sort_order")
        .execute()
        .data
        or []
    )
    return [_safe_recharge_plan(row) for row in rows]


def _issue_recharge_upload_ticket(storage_key: str, email: str) -> str:
    payload = {"storage_key": storage_key, "email": _normalize_email(email), "exp": int(time.time()) + 1800}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def _read_recharge_upload_ticket(ticket: str | None, email: str) -> dict[str, Any] | None:
    try:
        body, sig = (ticket or "").split(".", 1)
        expected = _b64encode(hmac.new(SERVER_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64decode(body).decode())
        if int(payload.get("exp") or 0) < int(time.time()):
            return None
        if _normalize_email(payload.get("email")) != _normalize_email(email):
            return None
        if not (payload.get("storage_key") or "").startswith("bank-import/recharge-proofs/"):
            return None
        return payload
    except Exception:
        return None


def _recharge_proof_ticket(data: dict[str, Any], email: str) -> tuple[dict[str, Any] | None, Any]:
    if not _r2_is_configured():
        return None, (
            jsonify({
                "success": False,
                "message": "Payment screenshot storage is not configured yet. Submit your recharge request using UTR number without an attachment.",
            }),
            503,
        )
    try:
        filename = _safe_recharge_screenshot_filename(data.get("filename") or "")
        content_type = (data.get("content_type") or "application/octet-stream").strip()
        size_bytes = int(data.get("size_bytes") or 0)
    except (TypeError, ValueError) as exc:
        return None, (jsonify({"success": False, "message": str(exc)}), 400)
    if size_bytes <= 0:
        return None, (jsonify({"success": False, "message": "Selected payment proof is empty."}), 400)
    if size_bytes > MAX_RECHARGE_SCREENSHOT_MB * 1024 * 1024:
        return None, (jsonify({"success": False, "message": f"Payment proof is larger than the {MAX_RECHARGE_SCREENSHOT_MB} MB limit."}), 400)
    storage_key = _new_recharge_screenshot_storage_key(email, filename)
    upload_url = _r2_presigned_put(storage_key, content_type)
    return {
        "success": True,
        "upload_url": upload_url,
        "storage_key": storage_key,
        "attachment_ticket": _issue_recharge_upload_ticket(storage_key, email),
        "headers": {"Content-Type": content_type},
        "expires_in": R2_UPLOAD_URL_SECONDS,
    }, None


def _wallet_customer_or_error(auth: dict[str, Any] | None):
    customer = _customer_for_auth(auth)
    if not customer or not customer.get("id"):
        return None, (jsonify({"success": False, "message": "Approved customer account not found."}), 404)
    return customer, None


@app.route("/customer/bank-import/temp-storage/status", methods=["GET"])
def customer_bank_import_temp_storage_status():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    configured = _bank_import_temp_r2_is_configured()
    same_bucket = bool(BANK_IMPORT_TEMP_R2_BUCKET_NAME and BANK_IMPORT_TEMP_R2_BUCKET_NAME == R2_BUCKET_NAME)
    return jsonify({
        "success": True,
        "configured": configured,
        "same_bucket_error": same_bucket,
        "max_pdf_mb": MAX_BANK_IMPORT_PDF_MB,
        "upload_url_seconds": BANK_IMPORT_TEMP_UPLOAD_URL_SECONDS,
        "retention_hours": BANK_IMPORT_TEMP_RETENTION_HOURS,
        "message": (
            "Temporary PDF storage is ready."
            if configured
            else "Create the separate tezhisab-bank-import-temp R2 bucket and add BANK_IMPORT_TEMP_R2_BUCKET_NAME in Render."
        ),
    })


@app.route("/customer/bank-import/statements/presign-upload", methods=["POST"])
def customer_bank_import_statement_presign_upload():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    if not _bank_import_temp_r2_is_configured():
        return jsonify({
            "success": False,
            "message": "Temporary PDF storage is not configured. Create a separate tezhisab-bank-import-temp R2 bucket and add BANK_IMPORT_TEMP_R2_BUCKET_NAME in Render.",
        }), 503
    _cleanup_expired_bank_import_temp_uploads(limit=10)
    data = request.json or {}
    try:
        filename = _safe_bank_import_pdf_filename(data.get("filename") or "")
        size_bytes = int(data.get("size_bytes") or 0)
    except (TypeError, ValueError) as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if size_bytes <= 0:
        return jsonify({"success": False, "message": "Selected PDF statement is empty."}), 400
    if size_bytes > MAX_BANK_IMPORT_PDF_MB * 1024 * 1024:
        return jsonify({"success": False, "message": f"PDF statement is larger than the configured {MAX_BANK_IMPORT_PDF_MB} MB limit."}), 400
    email = auth.get("email") or customer.get("email") or ""
    customer_id = int(customer.get("id"))
    storage_key = _new_bank_import_temp_storage_key(customer_id, email, filename)
    expires_at = (datetime.utcnow() + timedelta(hours=BANK_IMPORT_TEMP_RETENTION_HOURS)).isoformat()
    payload = {
        "customer_id": customer_id,
        "uploaded_by_email": _normalize_email(email),
        "storage_key": storage_key,
        "original_filename": filename,
        "content_type": "application/pdf",
        "size_bytes": size_bytes,
        "status": "upload_url_created",
        "expires_at": expires_at,
    }
    try:
        created = supabase.table("bank_import_temp_uploads").insert(payload).execute().data or []
        row = (created or [None])[0]
        if not row or not row.get("id"):
            raise RuntimeError("Temporary upload record was not created.")
        upload_url = _bank_import_temp_presigned_put(storage_key)
    except Exception as exc:
        return jsonify({
            "success": False,
            "message": "Could not prepare secure temporary PDF upload. Run the latest V16 Supabase SQL and verify the temporary R2 bucket settings.",
            "error": str(exc),
        }), 500
    ticket = _issue_bank_import_temp_upload_ticket(int(row.get("id")), storage_key, customer_id, email, size_bytes)
    _write_log("bank_import_temp_pdf_upload_url_created", {"upload_id": row.get("id"), "customer_id": customer_id, "size_bytes": size_bytes}, request)
    return jsonify({
        "success": True,
        "upload_id": row.get("id"),
        "upload_url": upload_url,
        "upload_ticket": ticket,
        "headers": {"Content-Type": "application/pdf"},
        "expires_in": BANK_IMPORT_TEMP_UPLOAD_URL_SECONDS,
        "retention_hours": BANK_IMPORT_TEMP_RETENTION_HOURS,
        "max_pdf_mb": MAX_BANK_IMPORT_PDF_MB,
        "message": "Secure temporary upload URL created.",
    })


@app.route("/customer/bank-import/statements/confirm-upload", methods=["POST"])
def customer_bank_import_statement_confirm_upload():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    data = request.json or {}
    try:
        upload_id = int(data.get("upload_id") or 0)
    except Exception:
        upload_id = 0
    customer_id = int(customer.get("id"))
    email = auth.get("email") or customer.get("email") or ""
    ticket = _read_bank_import_temp_upload_ticket(data.get("upload_ticket"), customer_id, email)
    if not upload_id or not ticket or int(ticket.get("upload_id") or 0) != upload_id:
        return jsonify({"success": False, "message": "Temporary upload authorization expired. Select the PDF statement again."}), 400
    rows = (
        supabase.table("bank_import_temp_uploads")
        .select("*")
        .eq("id", upload_id)
        .eq("customer_id", customer_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    row = (rows or [None])[0]
    if not row or row.get("storage_key") != ticket.get("storage_key"):
        return jsonify({"success": False, "message": "Temporary PDF upload record was not found."}), 404
    if (row.get("status") or "") not in {"upload_url_created", "uploaded"}:
        return jsonify({"success": False, "message": "This temporary PDF upload is no longer active."}), 400
    try:
        head = _bank_import_temp_r2_client().head_object(Bucket=BANK_IMPORT_TEMP_R2_BUCKET_NAME, Key=row.get("storage_key"))
        actual_size = int(head.get("ContentLength") or 0)
        if actual_size != int(row.get("size_bytes") or 0) or actual_size != int(ticket.get("size_bytes") or 0):
            _delete_bank_import_temp_object(row.get("storage_key") or "")
            supabase.table("bank_import_temp_uploads").update({"status": "failed", "failure_reason": "Uploaded PDF size verification failed.", "deleted_at": datetime.utcnow().isoformat()}).eq("id", upload_id).execute()
            return jsonify({"success": False, "message": "Uploaded PDF size verification failed. Select the statement again."}), 400
        actual_type = (head.get("ContentType") or "application/pdf").split(";", 1)[0].strip().lower()
        if actual_type != "application/pdf":
            _delete_bank_import_temp_object(row.get("storage_key") or "")
            supabase.table("bank_import_temp_uploads").update({"status": "failed", "failure_reason": "Uploaded file was not a PDF.", "deleted_at": datetime.utcnow().isoformat()}).eq("id", upload_id).execute()
            return jsonify({"success": False, "message": "Only PDF bank statements are allowed."}), 400
        updated = (
            supabase.table("bank_import_temp_uploads")
            .update({"status": "uploaded", "uploaded_at": datetime.utcnow().isoformat()})
            .eq("id", upload_id)
            .execute()
            .data
            or []
        )
        row = (updated or [row])[0]
    except Exception as exc:
        return jsonify({"success": False, "message": "Uploaded PDF could not be verified in temporary cloud storage.", "error": str(exc)}), 400
    _write_log("bank_import_temp_pdf_uploaded", {"upload_id": upload_id, "customer_id": customer_id, "size_bytes": row.get("size_bytes")}, request)
    return jsonify({
        "success": True,
        "upload": _safe_bank_import_temp_upload(row),
        "message": "PDF uploaded securely. It will be deleted automatically after processing.",
    })


@app.route("/customer/bank-import/processing/status", methods=["GET"])
def customer_bank_import_processing_status():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    return jsonify({
        "success": True,
        "temporary_storage_ready": _bank_import_temp_r2_is_configured(),
        "processor": processor_capabilities(),
        "wallet": _safe_wallet(_wallet_for_customer(int(customer.get("id")))),
        "wallet_deduction_enabled": True,
        "message": "Phase 4 wallet protection is ready: pages are reserved before extraction, deducted only after success and released automatically after failure.",
    })


@app.route("/customer/bank-import/statements/<int:upload_id>/process", methods=["POST"])
def customer_bank_import_statement_process(upload_id: int):
    """Process a verified temporary PDF and charge wallet pages only after success.

    Phase 4 rules:
    - Count actual PDF pages after secure download.
    - Reserve those pages atomically before extraction, blocking concurrent spend.
    - Deduct wallet pages only after successful extraction and metadata save.
    - Release held pages automatically on every processing failure.
    - Return preview rows to the browser without persisting accounting entries.
    """
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    if not _bank_import_temp_r2_is_configured():
        return jsonify({"success": False, "message": "Temporary PDF storage is not configured on the server."}), 503

    customer_id = int(customer.get("id"))
    rows = (
        supabase.table("bank_import_temp_uploads")
        .select("*")
        .eq("id", int(upload_id))
        .eq("customer_id", customer_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    row = (rows or [None])[0]
    if not row:
        return jsonify({"success": False, "message": "Temporary PDF upload record was not found."}), 404
    if (row.get("status") or "") != "uploaded":
        return jsonify({
            "success": False,
            "message": "This PDF is no longer available for processing. Upload and verify the statement again. Duplicate processing is blocked.",
        }), 409

    data = request.json or {}
    password = str(data.get("password") or "")[:200]
    requested_bank = str(data.get("bank") or "AUTO")[:60]
    storage_key = str(row.get("storage_key") or "")
    deleted_from_r2 = False
    cleanup_warning = ""
    processor_result: dict[str, Any] | None = None
    failure_message = ""
    reservation_id = 0
    reserved_pages = 0
    rollback_released = False

    try:
        with tempfile.TemporaryDirectory(prefix="bank-import-") as temp_dir:
            local_pdf = str(Path(temp_dir) / "statement.pdf")
            _bank_import_temp_r2_client().download_file(BANK_IMPORT_TEMP_R2_BUCKET_NAME, storage_key, local_pdf)
            actual_pages = int(count_pdf_pages(local_pdf, password=password) or 0)
            if actual_pages <= 0:
                raise RuntimeError("No readable pages were found in this PDF statement.")

            try:
                reservation = _rpc_first(
                    supabase.rpc(
                        "reserve_bank_import_pages",
                        {
                            "p_customer_id": customer_id,
                            "p_upload_id": int(upload_id),
                            "p_pages": actual_pages,
                            "p_created_by": auth.get("email") or "customer",
                        },
                    ).execute().data
                )
            except Exception as exc:
                raise RuntimeError(
                    "Wallet page reservation failed. Ensure that sufficient valid pages are available and run the latest V16 Supabase SQL before testing. "
                    + str(exc)
                ) from exc
            reservation_id = int(reservation.get("reservation_id") or 0)
            reserved_pages = int(reservation.get("pages_reserved") or actual_pages)
            if reservation_id <= 0:
                raise RuntimeError("Wallet reservation ID was not created. Run the latest V16 Supabase SQL and process again.")

            processor_result = process_bank_statement(local_pdf, password=password, bank=requested_bank)
    except Exception as exc:
        failure_message = str(exc).strip() or f"PDF processing failed: {type(exc).__name__}"
    finally:
        deleted_from_r2, delete_error = _delete_bank_import_temp_object(storage_key)
        if not deleted_from_r2 and delete_error:
            cleanup_warning = "Temporary PDF cleanup could not be confirmed; the R2 one-day lifecycle rule will remove it automatically."

    if failure_message or not processor_result:
        if reservation_id:
            rollback_released, rollback_error = _release_bank_import_reservation(reservation_id, failure_message or "PDF processing failed.")
            if rollback_error:
                failure_message += (" " if failure_message else "") + "Wallet rollback could not be confirmed automatically. Contact support before processing another statement."
        if cleanup_warning:
            failure_message += (" " if failure_message else "") + cleanup_warning
        try:
            supabase.table("bank_import_temp_uploads").update({
                "status": "failed",
                "failure_reason": failure_message[:1000],
                "deleted_at": datetime.utcnow().isoformat() if deleted_from_r2 else None,
            }).eq("id", int(upload_id)).execute()
        except Exception:
            pass
        wallet = _safe_wallet(_wallet_for_customer(customer_id))
        _write_log("bank_import_pdf_processing_failed", {
            "upload_id": int(upload_id),
            "customer_id": customer_id,
            "pdf_deleted": deleted_from_r2,
            "reservation_id": reservation_id,
            "wallet_rollback_released": rollback_released,
            "error": failure_message[:500],
        }, request)
        return jsonify({
            "success": False,
            "message": failure_message,
            "pdf_deleted": deleted_from_r2,
            "wallet_rollback_released": rollback_released,
            "wallet": wallet,
        }), 400

    transactions = list(processor_result.pop("transactions", []) or [])
    processed_at = datetime.utcnow().isoformat()
    metadata = {
        # Final wallet RPC changes this to processed atomically with deduction.
        "status": "processing",
        "deleted_at": processed_at if deleted_from_r2 else None,
        "page_count": int(processor_result.get("page_count") or reserved_pages),
        "bank_name": str(processor_result.get("bank") or "UNKNOWN")[:120],
        "extraction_mode": str(processor_result.get("extraction_mode") or "digital")[:30],
        "transaction_count": int(processor_result.get("total") or len(transactions)),
        "processing_summary": {
            "duplicates_detected": int(processor_result.get("duplicates_detected") or 0),
            "review_count": int(processor_result.get("review_count") or 0),
            "balance_mismatch_count": int(processor_result.get("balance_mismatch_count") or 0),
            "ocr_confidence": float(processor_result.get("ocr_confidence") or 0),
            "pdf_deleted": deleted_from_r2,
            "wallet_pages_reserved": reserved_pages,
        },
    }
    try:
        supabase.table("bank_import_temp_uploads").update(metadata).eq("id", int(upload_id)).execute()
        wallet_result = _rpc_first(
            supabase.rpc(
                "finalize_bank_import_pages",
                {
                    "p_reservation_id": reservation_id,
                    "p_created_by": auth.get("email") or "customer",
                    "p_description": f"Processed bank statement: {reserved_pages} page(s)",
                },
            ).execute().data
        )
        if not wallet_result:
            raise RuntimeError("Wallet deduction confirmation was not returned.")
    except Exception as exc:
        rollback_released, rollback_error = _release_bank_import_reservation(reservation_id, "Final wallet deduction could not be completed.")
        message = "Transactions were extracted, but final wallet deduction could not be completed. The held pages were released; upload and process the statement again."
        if rollback_error:
            message += " Automatic rollback could not be confirmed. Contact support before processing another statement."
        if cleanup_warning:
            message += " " + cleanup_warning
        try:
            supabase.table("bank_import_temp_uploads").update({
                "status": "failed",
                "failure_reason": (message + " " + str(exc))[:1000],
            }).eq("id", int(upload_id)).execute()
        except Exception:
            pass
        return jsonify({
            "success": False,
            "message": message,
            "error": str(exc),
            "pdf_deleted": deleted_from_r2,
            "wallet_rollback_released": rollback_released,
            "wallet": _safe_wallet(_wallet_for_customer(customer_id)),
        }), 500

    wallet = _safe_wallet(_wallet_for_customer(customer_id))
    _write_log("bank_import_pdf_processed", {
        "upload_id": int(upload_id),
        "customer_id": customer_id,
        "page_count": metadata["page_count"],
        "bank_name": metadata["bank_name"],
        "extraction_mode": metadata["extraction_mode"],
        "transaction_count": metadata["transaction_count"],
        "pdf_deleted": deleted_from_r2,
        "reservation_id": reservation_id,
        "wallet_pages_deducted": reserved_pages,
    }, request)
    message = str(processor_result.get("message") or "PDF processed successfully.")
    if cleanup_warning:
        message += " " + cleanup_warning
    return jsonify({
        "success": True,
        "processing": processor_result,
        "transactions": transactions,
        "pdf_deleted": deleted_from_r2,
        "wallet_deducted": True,
        "pages_deducted": reserved_pages,
        "wallet": wallet,
        "message": message,
    })


@app.route("/customer/bank-import/statements/<int:upload_id>", methods=["DELETE"])
def customer_bank_import_statement_delete(upload_id: int):
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    customer_id = int(customer.get("id"))
    rows = (
        supabase.table("bank_import_temp_uploads")
        .select("*")
        .eq("id", int(upload_id))
        .eq("customer_id", customer_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    row = (rows or [None])[0]
    if not row:
        return jsonify({"success": True, "message": "Temporary PDF was already removed."})
    if (row.get("status") or "") in {"deleted", "expired"}:
        return jsonify({"success": True, "message": "Temporary PDF was already removed."})
    if (row.get("status") or "") == "processing":
        return jsonify({"success": False, "message": "Processing is already running. Wait for the result before removing this PDF."}), 409
    reservation_id = int(row.get("reservation_id") or 0)
    if reservation_id:
        _release_bank_import_reservation(reservation_id, "Customer removed temporary PDF before processing completed.")
    ok, cloud_error = _delete_bank_import_temp_object(row.get("storage_key") or "")
    if not ok:
        return jsonify({"success": False, "message": "Temporary PDF could not be removed from cloud storage.", "error": cloud_error}), 500
    supabase.table("bank_import_temp_uploads").update({"status": "deleted", "deleted_at": datetime.utcnow().isoformat()}).eq("id", int(upload_id)).execute()
    _write_log("bank_import_temp_pdf_deleted", {"upload_id": int(upload_id), "customer_id": customer_id}, request)
    return jsonify({"success": True, "message": "Temporary PDF deleted from cloud storage."})


@app.route("/admin/bank-import/temp-storage/cleanup", methods=["POST"])
def admin_bank_import_temp_storage_cleanup():
    denied = _require_admin_json()
    if denied:
        return denied
    data = request.json or {}
    try:
        limit = int(data.get("limit") or 100)
    except Exception:
        limit = 100
    result = _cleanup_expired_bank_import_temp_uploads(limit=limit)
    _write_log("bank_import_temp_storage_cleanup", result, request)
    return jsonify({"success": True, "cleanup": result})


@app.route("/customer/bank-import/wallet", methods=["GET"])
def customer_bank_import_wallet():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    wallet = _safe_wallet(_wallet_for_customer(int(customer.get("id"))))
    requests_rows = (
        supabase.table("bank_import_recharge_requests")
        .select("*")
        .eq("customer_id", int(customer.get("id")))
        .order("submitted_at", desc=True)
        .limit(30)
        .execute()
        .data
        or []
    )
    transaction_rows = (
        supabase.table("bank_import_wallet_transactions")
        .select("*")
        .eq("customer_id", int(customer.get("id")))
        .order("created_at", desc=True)
        .limit(50)
        .execute()
        .data
        or []
    )
    return jsonify({
        "success": True,
        "wallet": wallet,
        "plans": _active_bank_import_plans(),
        "payment_settings": _bank_import_payment_settings(),
        "recharge_requests": [_safe_recharge_request(row) for row in requests_rows],
        "transactions": transaction_rows,
        "proof_upload_enabled": _r2_is_configured(),
        "max_recharge_screenshot_mb": MAX_RECHARGE_SCREENSHOT_MB,
        "privacy_note": "Tally ledgers, ledger mappings, narration groups and accounting entries are not stored in the Tezhisab cloud.",
    })


@app.route("/customer/bank-import/recharge/presign-upload", methods=["POST"])
def customer_bank_import_recharge_presign_upload():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    ticket, error = _recharge_proof_ticket(request.json or {}, auth.get("email") or customer.get("email") or "")
    return error or jsonify(ticket)


@app.route("/customer/bank-import/recharge-requests", methods=["POST"])
def customer_bank_import_recharge_request_create():
    auth, denied = _require_customer_auth()
    if denied:
        return denied
    customer, error = _wallet_customer_or_error(auth)
    if error:
        return error
    data = request.json or {}
    try:
        plan_id = int(data.get("plan_id") or 0)
    except Exception:
        plan_id = 0
    plan_rows = supabase.table("bank_import_recharge_plans").select("*").eq("id", plan_id).eq("status", "active").limit(1).execute().data or []
    if not plan_rows:
        return jsonify({"success": False, "message": "Select an active recharge plan."}), 400
    plan = _safe_recharge_plan(plan_rows[0])
    utr_number = (data.get("utr_number") or "").strip().upper()
    if len(utr_number) < 5:
        return jsonify({"success": False, "message": "Enter the payment UTR / transaction reference number."}), 400
    proof_key = (data.get("proof_storage_key") or "").strip()
    proof_ticket = _read_recharge_upload_ticket(data.get("attachment_ticket"), auth.get("email") or "") if proof_key else None
    if proof_key and (not proof_ticket or proof_ticket.get("storage_key") != proof_key):
        return jsonify({"success": False, "message": "Payment proof upload authorization expired. Select and upload the screenshot again."}), 400
    payload = {
        "customer_id": int(customer.get("id")),
        "plan_id": int(plan.get("id")),
        "plan_name": plan.get("plan_name") or "Recharge Plan",
        "requested_pages": int(plan.get("pages") or 0),
        "amount": float(plan.get("amount") or 0),
        "validity_days": int(plan.get("validity_days") or 365),
        "utr_number": utr_number,
        "payment_date": (data.get("payment_date") or today_str()).strip(),
        "customer_note": (data.get("customer_note") or "").strip(),
        "proof_storage_key": proof_key if proof_key.startswith("bank-import/recharge-proofs/") else "",
        "proof_filename": _safe_recharge_screenshot_filename(data.get("proof_filename")) if data.get("proof_filename") else "",
        "proof_content_type": (data.get("proof_content_type") or "").strip(),
        "proof_size_bytes": int(data.get("proof_size_bytes") or 0),
        "status": "pending",
    }
    try:
        created = supabase.table("bank_import_recharge_requests").insert(payload).execute().data or []
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not submit recharge request. Check whether this UTR was already submitted.", "error": str(exc)}), 400
    _write_log("bank_import_recharge_requested", {"customer_id": customer.get("id"), "plan_id": plan_id, "pages": plan.get("pages"), "utr": utr_number}, request)
    return jsonify({"success": True, "message": "Recharge request submitted. Pages will be added after admin approval.", "request": _safe_recharge_request((created or [payload])[0])})


def _proof_redirect_for_request(request_id: int, auth: dict[str, Any]):
    rows = supabase.table("bank_import_recharge_requests").select("*").eq("id", int(request_id)).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Payment proof not found."}), 404
    item = rows[0]
    if auth.get("role") != "admin":
        customer = _customer_for_auth(auth)
        if not customer or int(item.get("customer_id") or 0) != int(customer.get("id") or 0):
            return jsonify({"success": False, "message": "This payment proof does not belong to your account."}), 403
    key = (item.get("proof_storage_key") or "").strip()
    if not key or not _r2_is_configured():
        return jsonify({"success": False, "message": "Payment proof is unavailable."}), 404
    return redirect(_r2_presigned_get(key), code=302)


@app.route("/customer/bank-import/recharge-requests/<int:request_id>/proof", methods=["GET"])
def customer_bank_import_recharge_proof(request_id: int):
    auth = _portal_user_from_request(request)
    if not auth or auth.get("role") not in ("customer", "admin"):
        return jsonify({"success": False, "message": "Customer login required."}), 401
    return _proof_redirect_for_request(request_id, auth)


@app.route("/admin/bank-import/overview", methods=["GET"])
def admin_bank_import_overview():
    denied = _require_admin_json()
    if denied:
        return denied
    wallet_rows = supabase.table("bank_import_wallets").select("*,customers(name,email,business_name,phone)").order("updated_at", desc=True).execute().data or []
    request_rows = supabase.table("bank_import_recharge_requests").select("*,customers(name,email,business_name,phone)").order("submitted_at", desc=True).limit(200).execute().data or []
    plan_rows = supabase.table("bank_import_recharge_plans").select("*").order("sort_order").execute().data or []
    wallets = []
    for row in wallet_rows:
        item = _safe_wallet(row)
        item["customers"] = row.get("customers") or {}
        wallets.append(item)
    pending = sum(1 for row in request_rows if (row.get("status") or "pending") == "pending")
    return jsonify({
        "success": True,
        "wallets": wallets,
        "recharge_requests": [_safe_recharge_request(row) for row in request_rows],
        "plans": [_safe_recharge_plan(row) for row in plan_rows],
        "payment_settings": _bank_import_payment_settings(),
        "summary": {
            "customers_with_wallet": len(wallets),
            "pages_remaining": sum(int(item.get("page_balance") or 0) for item in wallets),
            "pages_credited": sum(int(item.get("total_pages_credited") or 0) for item in wallets),
            "pending_requests": pending,
        },
        "proof_upload_enabled": _r2_is_configured(),
        "max_recharge_screenshot_mb": MAX_RECHARGE_SCREENSHOT_MB,
    })


@app.route("/admin/bank-import/recharge-plans", methods=["POST"])
def admin_bank_import_recharge_plan_create():
    denied = _require_admin_json()
    if denied:
        return denied
    data = request.json or {}
    plan_name = (data.get("plan_name") or "").strip()
    try:
        pages = int(data.get("pages") or 0)
        amount = float(data.get("amount") or 0)
        validity_days = int(data.get("validity_days") or 365)
        sort_order = int(data.get("sort_order") or 100)
    except Exception:
        return jsonify({"success": False, "message": "Pages, amount, validity days and display order must be valid numbers."}), 400
    if not plan_name or pages <= 0 or amount < 0 or validity_days <= 0:
        return jsonify({"success": False, "message": "Plan name, positive pages and positive validity days are required."}), 400
    payload = {"plan_name": plan_name, "pages": pages, "amount": amount, "validity_days": validity_days, "sort_order": sort_order, "status": "active" if data.get("status") == "active" else "inactive"}
    created = supabase.table("bank_import_recharge_plans").insert(payload).execute().data or []
    _write_log("bank_import_recharge_plan_created", payload, request)
    return jsonify({"success": True, "message": "Recharge plan saved successfully.", "plan": _safe_recharge_plan((created or [payload])[0])})


@app.route("/admin/bank-import/recharge-plans/<int:plan_id>/status", methods=["POST"])
def admin_bank_import_recharge_plan_status(plan_id: int):
    denied = _require_admin_json()
    if denied:
        return denied
    status = ((request.json or {}).get("status") or "").strip().lower()
    if status not in {"active", "inactive"}:
        return jsonify({"success": False, "message": "Plan status must be active or inactive."}), 400
    supabase.table("bank_import_recharge_plans").update({"status": status, "updated_at": datetime.utcnow().isoformat() + "Z"}).eq("id", int(plan_id)).execute()
    return jsonify({"success": True, "message": f"Recharge plan marked as {status}."})


@app.route("/admin/bank-import/payment-settings", methods=["POST"])
def admin_bank_import_payment_settings_save():
    denied = _require_admin_json()
    if denied:
        return denied
    data = request.json or {}
    payload = {
        "id": 1,
        "receiver_name": (data.get("receiver_name") or "").strip(),
        "upi_id": (data.get("upi_id") or "").strip(),
        "payment_note": (data.get("payment_note") or "").strip(),
        "qr_image_url": (data.get("qr_image_url") or "").strip(),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    supabase.table("bank_import_payment_settings").upsert(payload, on_conflict="id").execute()
    _write_log("bank_import_payment_settings_updated", {"receiver_name": payload["receiver_name"], "upi_id": payload["upi_id"]}, request)
    return jsonify({"success": True, "message": "Manual payment details updated successfully.", "payment_settings": payload})


@app.route("/admin/bank-import/recharge-requests/<int:request_id>/approve", methods=["POST"])
def admin_bank_import_recharge_approve(request_id: int):
    denied = _require_admin_json()
    if denied:
        return denied
    auth = _current_user(request) or {}
    try:
        result = supabase.rpc("approve_bank_import_recharge", {"p_request_id": int(request_id), "p_admin_email": auth.get("email") or "admin"}).execute().data or []
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not approve recharge. Run the latest Phase 4 SQL file first or check whether the request is still pending.", "error": str(exc)}), 400
    _write_log("bank_import_recharge_approved", {"request_id": request_id}, request)
    return jsonify({"success": True, "message": "Recharge approved. Pages have been added to the customer wallet.", "result": result})


@app.route("/admin/bank-import/recharge-requests/<int:request_id>/reject", methods=["POST"])
def admin_bank_import_recharge_reject(request_id: int):
    denied = _require_admin_json()
    if denied:
        return denied
    auth = _current_user(request) or {}
    data = request.json or {}
    reason = (data.get("reason") or "Payment could not be verified.").strip()
    rows = supabase.table("bank_import_recharge_requests").select("*").eq("id", int(request_id)).limit(1).execute().data or []
    if not rows:
        return jsonify({"success": False, "message": "Recharge request not found."}), 404
    if (rows[0].get("status") or "pending") != "pending":
        return jsonify({"success": False, "message": "Only pending recharge requests can be rejected."}), 400
    supabase.table("bank_import_recharge_requests").update({"status": "rejected", "rejection_reason": reason, "reviewed_by": auth.get("email") or "admin", "reviewed_at": datetime.utcnow().isoformat() + "Z"}).eq("id", int(request_id)).execute()
    _write_log("bank_import_recharge_rejected", {"request_id": request_id, "reason": reason}, request)
    return jsonify({"success": True, "message": "Recharge request rejected."})


@app.route("/admin/bank-import/recharge-requests/<int:request_id>/proof", methods=["GET"])
def admin_bank_import_recharge_proof(request_id: int):
    auth = _portal_user_from_request(request)
    if not auth or auth.get("role") != "admin":
        return jsonify({"success": False, "message": "Admin login required."}), 401
    return _proof_redirect_for_request(request_id, auth)


@app.route("/admin/bank-import/wallet-adjustments", methods=["POST"])
def admin_bank_import_wallet_adjustment():
    denied = _require_admin_json()
    if denied:
        return denied
    data = request.json or {}
    auth = _current_user(request) or {}
    try:
        customer_id = int(data.get("customer_id") or 0)
        pages_delta = int(data.get("pages_delta") or 0)
        validity_days = int(data.get("validity_days") or 0)
    except Exception:
        return jsonify({"success": False, "message": "Customer, pages and validity extension must be valid numbers."}), 400
    if not customer_id or (pages_delta == 0 and validity_days == 0):
        return jsonify({"success": False, "message": "Select a customer and enter pages to add/remove or validity days to extend."}), 400
    description = (data.get("description") or "Manual wallet adjustment").strip()
    try:
        result = supabase.rpc("adjust_bank_import_wallet", {"p_customer_id": customer_id, "p_pages_delta": pages_delta, "p_validity_days": validity_days, "p_admin_email": auth.get("email") or "admin", "p_description": description}).execute().data or []
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not update wallet. Run the latest Phase 4 SQL file first and ensure balance will not become negative.", "error": str(exc)}), 400
    _write_log("bank_import_wallet_adjusted", {"customer_id": customer_id, "pages_delta": pages_delta, "validity_days": validity_days}, request)
    return jsonify({"success": True, "message": "Customer wallet updated successfully.", "result": result})


@app.route("/admin/activity-logs", methods=["GET"])
def admin_activity_logs():
    denied = _require_admin_json()
    if denied: return denied
    resp = supabase.table("activity_logs").select("*").order("created_at", desc=True).limit(100).execute()
    return jsonify({"success": True, "logs": resp.data or []})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
