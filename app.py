import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, request, send_from_directory
from supabase import Client, create_client
from werkzeug.utils import secure_filename

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

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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


def _new_storage_key(channel: dict[str, Any], version: str, filename: str) -> str:
    product = _clean_path_piece(channel.get("product_code"), "software").lower()
    channel_code = _clean_path_piece(channel.get("channel_code"), "channel").lower()
    version_piece = _clean_path_piece(version, "version")
    safe_name = _safe_app_filename(filename)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    random_piece = secrets.token_hex(4)
    return f"apps/{product}/{channel_code}/{version_piece}/{stamp}_{random_piece}_{safe_name}"


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


def _cleanup_old_cloud_versions(channel_id: int, keep_count: int | None = None) -> dict[str, Any]:
    """Keep only the newest central-cloud files for one software channel."""
    keep = max(1, int(keep_count or APP_VERSION_RETENTION_COUNT))
    rows = (
        supabase.table("app_versions")
        .select("*")
        .eq("channel_id", int(channel_id))
        .eq("published", True)
        .order("created_at", desc=True)
        .execute()
        .data
        or []
    )
    cloud_rows = [row for row in rows if (row.get("storage_key") or "").strip()]
    removed: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for row in cloud_rows[keep:]:
        ok, error = _delete_cloud_version(row)
        item = {"id": row.get("id"), "version": row.get("version"), "storage_key": row.get("storage_key")}
        if ok:
            removed.append(item)
        else:
            item["error"] = error
            failed.append(item)
    return {"channel_id": int(channel_id), "keep_count": keep, "removed": removed, "failed": failed}


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


def _portal_user_from_request(req) -> dict[str, Any] | None:
    return _current_user(req) or _read_token(req.args.get("token"))


def _version_response(version: dict[str, Any] | None, include_presigned_download: bool = False) -> dict[str, Any] | None:
    if not version:
        return None
    item = dict(version)
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
    }).execute()
    return jsonify({
        "success": True,
        "key": key,
        "product": product_code,
        "product_name": product["product_name"],
        "expires_on": expires_on,
        "license_mode": license_mode,
        "validity_days": validity_days,
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
    resp = supabase.table("app_versions").select("*,update_channels(product_code,channel_code,channel_name)").order("created_at", desc=True).execute()
    product_map = get_product_map(include_inactive=True)
    versions = []
    latest_channels: set[int] = set()
    for row in (resp.data or []):
        item = dict(row)
        channel = dict(item.get("update_channels") or {})
        product = product_map.get(normalize_product(channel.get("product_code")))
        channel["product_name"] = (product or {}).get("product_name") or channel.get("product_code") or "Software"
        item["update_channels"] = channel
        channel_id = int(item.get("channel_id") or 0)
        item["is_latest"] = bool(channel_id and channel_id not in latest_channels)
        if channel_id:
            latest_channels.add(channel_id)
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
    payload = {"channel_id": int(channel_id), "version": version, "download_url": download_url, "notes": notes, "mandatory": bool(data.get("mandatory")), "published": True}
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
    storage_key = _new_storage_key(channel, version, filename)
    try:
        upload_url = _r2_presigned_put(storage_key, content_type)
    except Exception as exc:
        return jsonify({"success": False, "message": "Could not prepare the secure cloud upload URL.", "error": str(exc)}), 500
    _write_log("central_upload_url_created", {"channel_id": channel_id, "version": version, "storage_key": storage_key, "size_bytes": size_bytes}, request)
    return jsonify({
        "success": True,
        "upload_url": upload_url,
        "storage_key": storage_key,
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
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid channel or file size."}), 400
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
    payload = {
        "channel_id": channel_id,
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
        return jsonify({"success": False, "message": "Could not publish this upload. Run the latest Phase 2 SQL file first, or use a different version number.", "error": str(exc)}), 500
    cleanup = {"removed": [], "failed": [], "keep_count": APP_VERSION_RETENTION_COUNT}
    if AUTO_DELETE_OLDER_VERSIONS:
        cleanup = _cleanup_old_cloud_versions(channel_id, APP_VERSION_RETENTION_COUNT)
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
    versions = supabase.table("app_versions").select("*").eq("published", True).order("created_at", desc=True).execute().data or []
    latest_by_channel = {}
    for version in versions:
        latest_by_channel.setdefault(version.get("channel_id"), _version_response(version, include_presigned_download=False))
    products = []
    for lic in licenses:
        product_channels = []
        for channel in channels:
            if slug_code(channel.get("product_code") or "") == lic.get("product_code"):
                item = dict(channel)
                item["latest_version"] = latest_by_channel.get(channel.get("id"))
                product_channels.append(item)
        products.append({"license": lic, "channels": product_channels})
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
    if auth.get("role") != "admin" and not _active_license_for_email_product(auth.get("email") or "", product_code):
        return jsonify({"success": False, "message": "This software is not assigned to your active customer account."}), 403
    storage_key = (version.get("storage_key") or "").strip()
    if storage_key:
        if not _r2_is_configured():
            return jsonify({"success": False, "message": "Cloud download is temporarily unavailable. Please contact Tezhisab support."}), 503
        url = _r2_presigned_get(storage_key)
    else:
        url = (version.get("download_url") or "").strip()
        if not url.lower().startswith(("https://", "http://")):
            return jsonify({"success": False, "message": "Download link is not configured."}), 404
    _write_log("customer_app_download", {"version_id": version_id, "product_code": product_code, "email": auth.get("email")}, request)
    return redirect(url, code=302)


def _latest_channel_version(product_code: str, channel_code: str):
    product_code = normalize_product(product_code)
    channel_code = channel_slug(channel_code)
    channel_rows = supabase.table("update_channels").select("*").eq("product_code", product_code).eq("channel_code", channel_code).limit(1).execute().data or []
    channel = (channel_rows or [None])[0]
    if not channel:
        # Backward compatibility for any earlier rows saved with truncated codes.
        possible = supabase.table("update_channels").select("*").eq("product_code", product_code).execute().data or []
        channel = next((row for row in possible if channel_slug(row.get("channel_code")) == channel_code), None)
    if not channel:
        return None, None
    versions = supabase.table("app_versions").select("*").eq("channel_id", channel.get("id")).eq("published", True).order("created_at", desc=True).limit(1).execute().data or []
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
    channel, latest = _latest_channel_version(product_code, channel_code)
    if not channel:
        return jsonify({"success": False, "message": "Update channel not configured."}), 404
    secure_latest = _version_response(latest, include_presigned_download=True)
    return jsonify({
        "success": True,
        "product": product_code,
        "channel": channel_code,
        "current_version": current_version,
        "latest": secure_latest,
        "update_available": bool(latest and latest.get("version") != current_version),
        "license_status": lic.get("status"),
        "license_expires_on": lic.get("expires_on"),
    })


@app.route("/admin/activity-logs", methods=["GET"])
def admin_activity_logs():
    denied = _require_admin_json()
    if denied: return denied
    resp = supabase.table("activity_logs").select("*").order("created_at", desc=True).limit(100).execute()
    return jsonify({"success": True, "logs": resp.data or []})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
