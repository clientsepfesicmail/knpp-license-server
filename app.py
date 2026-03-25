"""
KNPP Associate — Multi-Product License Server
Version 2.0

Endpoints:
  POST /activate              — Activate a license key on a machine
  POST /verify                — Verify license for a machine
  POST /admin/login           — Admin authenticate
  POST /admin/generate        — Admin generate new license key
  GET  /admin/licenses        — Admin list licenses (optional ?product=...)
  GET  /admin/dashboard       — Admin summary counts
  POST /admin/renew           — Admin renew a key by 1 year
  POST /admin/revoke_machine  — Admin remove one machine from a key
"""

import os
import hmac
import hashlib
import secrets
import string
from datetime import datetime, timedelta, date

from flask import Flask, request, jsonify, send_from_directory
from supabase import create_client, Client

app = Flask(__name__, static_folder="admin", static_url_path="")

# ── Environment / Config ───────────────────────────────────────
SUPABASE_URL   = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY   = os.environ.get("SUPABASE_KEY", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "knpp@admin2024")
SERVER_SECRET  = os.environ.get("SERVER_SECRET", "knpp_secret_key_change_this")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Product Master ─────────────────────────────────────────────
VALID_PRODUCTS = {
    "EPF_ESIC": "EPF & ESIC Manager",
    "TALLYSYNC_PRO": "TallySync Pro",
    "APP3": "App 3",
    "APP4": "App 4",
    "APP5": "App 5",
    "APP6": "App 6",
    "APP7": "App 7",
}

PRODUCT_PREFIX = {
    "EPF_ESIC": "EPF",
    "TALLYSYNC_PRO": "TSP",
    "APP3": "A03",
    "APP4": "A04",
    "APP5": "A05",
    "APP6": "A06",
    "APP7": "A07",
}

DEFAULT_PRODUCT = "EPF_ESIC"

# ── Helpers ────────────────────────────────────────────────────
def today_str() -> str:
    return date.today().isoformat()


def days_from_today(d_str: str) -> int:
    """Return days remaining from today to d_str (negative = expired)."""
    if not d_str:
        return 9999
    try:
        exp = date.fromisoformat(d_str)
        return (exp - date.today()).days
    except Exception:
        return 0


def normalize_product(product: str | None) -> str:
    p = (product or "").strip().upper()
    if not p:
        return DEFAULT_PRODUCT
    return p


def is_valid_product(product: str) -> bool:
    return product in VALID_PRODUCTS


def generate_key(product: str) -> str:
    """Generate a product-wise license key."""
    year = datetime.now().year
    part1 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    part2 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    prefix = PRODUCT_PREFIX.get(product, "GEN")
    raw = f"KNPP-{prefix}-{year}-{part1}-{part2}"
    chk = hmac.new(SERVER_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:4].upper()
    return f"{raw}-{chk}"


def verify_key_format(key: str) -> bool:
    """Verify checksum of license key."""
    parts = key.strip().upper().split("-")
    if len(parts) != 6:
        return False
    raw = "-".join(parts[:5])
    expected_chk = hmac.new(SERVER_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:4].upper()
    return parts[5] == expected_chk


def make_signature(key: str, machine_id: str, expires: str) -> str:
    """Create tamper-proof signature for local cache."""
    data = f"{key}|{machine_id}|{expires}|{SERVER_SECRET}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def check_admin(req) -> bool:
    token = req.headers.get("X-Admin-Token", "")
    return token == ADMIN_PASSWORD


def get_license_by_key(key: str):
    resp = supabase.table("licenses").select("*").eq("key", key).execute()
    if not resp.data:
        return None
    lic = resp.data[0]
    if not lic.get("product"):
        lic["product"] = DEFAULT_PRODUCT
    return lic


# ── Routes ─────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("admin", "index.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    if data.get("password") == ADMIN_PASSWORD:
        return jsonify({"success": True, "token": ADMIN_PASSWORD})
    return jsonify({"success": False, "message": "Invalid password"}), 401


@app.route("/activate", methods=["POST"])
def activate():
    """
    Body:
    {
      "key": "KNPP-...",
      "machine_id": "...",
      "machine_label": "PC Name",
      "product": "EPF_ESIC"
    }
    """
    data = request.json or {}

    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "").strip()
    machine_label = data.get("machine_label", "Unknown PC")
    product = normalize_product(data.get("product"))

    if not key or not machine_id or not product:
        return jsonify({
            "success": False,
            "message": "Key, Machine ID and Product are required."
        }), 400

    if not is_valid_product(product):
        return jsonify({
            "success": False,
            "message": f"Invalid product: {product}"
        }), 400

    if not verify_key_format(key):
        return jsonify({
            "success": False,
            "message": "Invalid license key format."
        }), 400

    lic = get_license_by_key(key)
    if not lic:
        return jsonify({
            "success": False,
            "message": "License key not found."
        }), 404

    lic_product = normalize_product(lic.get("product"))
    if lic_product != product:
        return jsonify({
            "success": False,
            "message": f"This license is not valid for product: {product}"
        }), 403

    days_left = days_from_today(lic.get("expires_on", ""))
    if days_left < 0:
        return jsonify({
            "success": False,
            "message": f"This license expired on {lic.get('expires_on')}.\nPlease renew. Contact: Pradip Majumder — 7896489317"
        }), 403

    machines = lic.get("machines", []) or []
    max_pcs = int(lic.get("max_pcs", 3) or 3)

    existing_ids = [m.get("id") for m in machines]

    if machine_id in existing_ids:
        sig = make_signature(key, machine_id, lic.get("expires_on", ""))
        return jsonify({
            "success": True,
            "message": "Already activated on this machine.",
            "expires": lic.get("expires_on", ""),
            "client_name": lic.get("client_name", ""),
            "days_left": days_left,
            "product": lic_product,
            "signature": sig
        })

    if len(machines) >= max_pcs:
        return jsonify({
            "success": False,
            "message": f"Maximum {max_pcs} PC limit reached for this license.\nPlease contact Pradip Majumder — 7896489317 to add more PCs."
        }), 403

    machines.append({
        "id": machine_id,
        "label": machine_label,
        "activated_on": today_str()
    })

    supabase.table("licenses").update({
        "machines": machines,
        "last_verified": today_str(),
        "product": lic_product
    }).eq("key", key).execute()

    sig = make_signature(key, machine_id, lic.get("expires_on", ""))
    return jsonify({
        "success": True,
        "message": "License activated successfully!",
        "expires": lic.get("expires_on", ""),
        "client_name": lic.get("client_name", ""),
        "days_left": days_left,
        "product": lic_product,
        "signature": sig
    })


@app.route("/verify", methods=["POST"])
def verify():
    """
    Body:
    {
      "key": "KNPP-...",
      "machine_id": "...",
      "product": "EPF_ESIC"
    }
    """
    data = request.json or {}

    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "").strip()
    product = normalize_product(data.get("product"))

    if not key or not machine_id or not product:
        return jsonify({
            "valid": False,
            "message": "Missing key, machine ID or product."
        }), 400

    if not is_valid_product(product):
        return jsonify({
            "valid": False,
            "message": f"Invalid product: {product}"
        }), 400

    lic = get_license_by_key(key)
    if not lic:
        return jsonify({
            "valid": False,
            "message": "License key not found."
        }), 404

    lic_product = normalize_product(lic.get("product"))
    if lic_product != product:
        return jsonify({
            "valid": False,
            "message": f"This license is not valid for product: {product}"
        }), 403

    machines = lic.get("machines", []) or []
    machine_ids = [m.get("id") for m in machines]

    if machine_id not in machine_ids:
        return jsonify({
            "valid": False,
            "message": "This machine is not registered for this license.\nPlease activate first or contact KNPP."
        }), 403

    days_left = days_from_today(lic.get("expires_on", ""))
    if days_left < 0:
        return jsonify({
            "valid": False,
            "message": f"License expired on {lic.get('expires_on')}.\nPlease renew. Contact: Pradip Majumder — 7896489317",
            "expires": lic.get("expires_on", ""),
            "days_left": days_left
        }), 403

    supabase.table("licenses").update({
        "last_verified": today_str(),
        "product": lic_product
    }).eq("key", key).execute()

    sig = make_signature(key, machine_id, lic.get("expires_on", ""))
    return jsonify({
        "valid": True,
        "expires": lic.get("expires_on", ""),
        "client_name": lic.get("client_name", ""),
        "product": lic_product,
        "days_left": days_left,
        "signature": sig,
        "message": "License valid."
    })


# ── Admin endpoints ────────────────────────────────────────────
@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json or {}

    client_name = data.get("client_name", "").strip()
    client_phone = data.get("client_phone", "").strip()
    client_email = data.get("client_email", "").strip()
    max_pcs = int(data.get("max_pcs", 3))
    notes = data.get("notes", "")
    product = normalize_product(data.get("product"))

    if not client_name:
        return jsonify({
            "success": False,
            "message": "Client name required."
        }), 400

    if not is_valid_product(product):
        return jsonify({
            "success": False,
            "message": f"Invalid product: {product}"
        }), 400

    key = generate_key(product)
    activated_on = today_str()
    expires_on = (date.today() + timedelta(days=365)).isoformat()

    supabase.table("licenses").insert({
        "key": key,
        "product": product,
        "client_name": client_name,
        "client_phone": client_phone,
        "client_email": client_email,
        "max_pcs": max_pcs,
        "machines": [],
        "activated_on": activated_on,
        "expires_on": expires_on,
        "last_verified": None,
        "status": "active",
        "notes": notes
    }).execute()

    return jsonify({
        "success": True,
        "key": key,
        "product": product,
        "product_name": VALID_PRODUCTS.get(product, product),
        "expires_on": expires_on,
        "message": f"License generated for {client_name}"
    })


@app.route("/admin/licenses", methods=["GET"])
def admin_licenses():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    product = normalize_product(request.args.get("product", "")).strip()
    raw_product = (request.args.get("product", "") or "").strip().upper()

    query = supabase.table("licenses").select("*")
    if raw_product and is_valid_product(raw_product):
        query = query.eq("product", raw_product)

    resp = query.order("activated_on", desc=True).execute()

    licenses = []
    for lic in (resp.data or []):
        lic_product = normalize_product(lic.get("product"))
        days_left = days_from_today(lic.get("expires_on", ""))

        lic["product"] = lic_product
        lic["product_name"] = VALID_PRODUCTS.get(lic_product, lic_product)
        lic["days_left"] = days_left

        if days_left < 0:
            lic["display_status"] = "expired"
        elif days_left <= 30:
            lic["display_status"] = "expiring_soon"
        else:
            lic["display_status"] = "active"

        licenses.append(lic)

    return jsonify({
        "success": True,
        "licenses": licenses
    })


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    resp = supabase.table("licenses").select("*").execute()
    data = resp.data or []

    total = len(data)
    active = sum(1 for l in data if days_from_today(l.get("expires_on", "")) >= 30)
    expiring_soon = sum(1 for l in data if 0 <= days_from_today(l.get("expires_on", "")) < 30)
    expired = sum(1 for l in data if days_from_today(l.get("expires_on", "")) < 0)
    total_pcs = sum(len(l.get("machines", []) or []) for l in data)

    product_counts = {}
    for code in VALID_PRODUCTS:
        product_counts[code] = sum(
            1 for l in data if normalize_product(l.get("product")) == code
        )

    return jsonify({
        "success": True,
        "total": total,
        "active": active,
        "expiring_soon": expiring_soon,
        "expired": expired,
        "total_pcs_activated": total_pcs,
        "product_counts": product_counts
    })


@app.route("/admin/renew", methods=["POST"])
def admin_renew():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json or {}
    key = data.get("key", "").strip().upper()

    if not key:
        return jsonify({
            "success": False,
            "message": "Key required."
        }), 400

    lic = get_license_by_key(key)
    if not lic:
        return jsonify({
            "success": False,
            "message": "Key not found."
        }), 404

    current_exp = lic.get("expires_on", today_str())
    try:
        base = date.fromisoformat(current_exp)
        if base < date.today():
            base = date.today()
    except Exception:
        base = date.today()

    new_expires = (base + timedelta(days=365)).isoformat()

    supabase.table("licenses").update({
        "expires_on": new_expires,
        "status": "active"
    }).eq("key", key).execute()

    return jsonify({
        "success": True,
        "message": f"Renewed! New expiry: {new_expires}",
        "new_expires": new_expires
    })


@app.route("/admin/revoke_machine", methods=["POST"])
def admin_revoke_machine():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json or {}
    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "").strip()

    if not key or not machine_id:
        return jsonify({
            "success": False,
            "message": "Key and machine_id required."
        }), 400

    lic = get_license_by_key(key)
    if not lic:
        return jsonify({
            "success": False,
            "message": "Key not found."
        }), 404

    machines = [m for m in (lic.get("machines", []) or []) if m.get("id") != machine_id]

    supabase.table("licenses").update({
        "machines": machines
    }).eq("key", key).execute()

    return jsonify({
        "success": True,
        "message": "Machine removed. Client can now activate on a new PC."
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "message": "License server is running."
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
