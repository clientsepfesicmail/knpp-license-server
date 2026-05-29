import hashlib
import hmac
import os
import secrets
import string
from datetime import date, datetime, timedelta
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from supabase import Client, create_client

app = Flask(__name__, static_folder="admin", static_url_path="")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "knpp@admin2024")
SERVER_SECRET = os.environ.get("SERVER_SECRET", "knpp_secret_key_change_this")
BRAND_NAME = "Tezhisab"
LICENSE_PREFIX = "PPPM"
DEFAULT_PRODUCT_CODE = "EEM"

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



def check_admin(req) -> bool:
    return req.headers.get("X-Admin-Token", "") == ADMIN_PASSWORD



def slug_code(value: str) -> str:
    cleaned = "".join(ch for ch in value.upper().strip() if ch.isalnum())
    return cleaned[:8]



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
    if days_left < 0:
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
    expires_on = (date.today() + timedelta(days=365)).isoformat()
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
        "status": "active",
        "notes": notes,
    }).execute()
    return jsonify({
        "success": True,
        "key": key,
        "product": product_code,
        "product_name": product["product_name"],
        "expires_on": expires_on,
        "message": f"License generated for {client_name}",
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
