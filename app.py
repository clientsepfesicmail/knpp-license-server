"""
KNPP Associate — EPF & ESIC Compliance Manager
License Server v1.0
Hosted on Railway.app

Endpoints:
  POST /activate          — Activate a license key on a machine
  POST /verify            — Verify license (called by app periodically)
  POST /revoke_machine    — Admin: remove one machine from a license
  POST /renew             — Admin: extend license by 1 year
  POST /generate          — Admin: generate new license key
  GET  /admin/licenses    — Admin: list all licenses
  GET  /admin/dashboard   — Admin: summary counts
  POST /admin/login       — Admin: authenticate
"""

import os
import hmac
import uuid
import hashlib
import secrets
import string
from datetime import datetime, timedelta, date

from flask import Flask, request, jsonify, send_from_directory
from supabase import create_client, Client

app = Flask(__name__, static_folder="admin", static_url_path="")

# ── Supabase connection ─────────────────────────────────────────
SUPABASE_URL      = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY      = os.environ.get("SUPABASE_KEY", "")
ADMIN_PASSWORD    = os.environ.get("ADMIN_PASSWORD", "knpp@admin2024")
SERVER_SECRET     = os.environ.get("SERVER_SECRET", "knpp_secret_key_change_this")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Helpers ─────────────────────────────────────────────────────
def today_str():
    return date.today().isoformat()


def days_from_today(d_str: str) -> int:
    """Return days remaining from today to d_str (negative = expired)"""
    if not d_str:
        return 9999
    try:
        exp = date.fromisoformat(d_str)
        return (exp - date.today()).days
    except Exception:
        return 0


def generate_key() -> str:
    """Generate a license key: KNPP-EPF-YYYY-XXXX-CCCC"""
    year = datetime.now().year
    part1 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    part2 = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    raw = f"KNPP-EPF-{year}-{part1}-{part2}"
    # Append a 4-char HMAC checksum
    chk = hmac.new(SERVER_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:4].upper()
    return f"{raw}-{chk}"


def verify_key_format(key: str) -> bool:
    """Verify the checksum of a license key"""
    parts = key.strip().upper().split("-")
    if len(parts) != 6:
        return False
    raw = "-".join(parts[:5])
    expected_chk = hmac.new(SERVER_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:4].upper()
    return parts[5] == expected_chk


def make_signature(key: str, machine_id: str, expires: str) -> str:
    """Create tamper-proof signature for local cache"""
    data = f"{key}|{machine_id}|{expires}|{SERVER_SECRET}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


# ── Admin Auth ──────────────────────────────────────────────────
def check_admin(req) -> bool:
    token = req.headers.get("X-Admin-Token", "")
    return token == ADMIN_PASSWORD


# ── Routes ──────────────────────────────────────────────────────

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
    Body: { "key": "KNPP-...", "machine_id": "...", "machine_label": "PC Name" }
    Response: { "success": bool, "message": str, "expires": "YYYY-MM-DD",
                "client_name": str, "signature": str }
    """
    data      = request.json or {}
    key       = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "").strip()
    machine_label = data.get("machine_label", "Unknown PC")

    if not key or not machine_id:
        return jsonify({"success": False, "message": "Key and Machine ID are required."}), 400

    if not verify_key_format(key):
        return jsonify({"success": False, "message": "Invalid license key format."}), 400

    # Fetch license from DB
    resp = supabase.table("licenses").select("*").eq("key", key).execute()
    if not resp.data:
        return jsonify({"success": False, "message": "License key not found."}), 404

    lic = resp.data[0]

    # Check expiry
    days_left = days_from_today(lic.get("expires_on", ""))
    if days_left < 0:
        return jsonify({
            "success": False,
            "message": f"This license expired on {lic.get('expires_on')}.\nPlease renew. Contact: Pradip Majumder — 7896489317"
        }), 403

    # Check existing machines
    machines = lic.get("machines", []) or []
    max_pcs  = lic.get("max_pcs", 3)

    # Already activated on this machine?
    if machine_id in [m.get("id") for m in machines]:
        sig = make_signature(key, machine_id, lic.get("expires_on", ""))
        return jsonify({
            "success": True,
            "message": "Already activated on this machine.",
            "expires": lic.get("expires_on", ""),
            "client_name": lic.get("client_name", ""),
            "days_left": days_left,
            "signature": sig
        })

    # Check PC limit
    if len(machines) >= max_pcs:
        return jsonify({
            "success": False,
            "message": f"Maximum {max_pcs} PC limit reached for this license.\n"
                       f"Please contact Pradip Majumder — 7896489317 to add more PCs."
        }), 403

    # Add machine
    machines.append({
        "id": machine_id,
        "label": machine_label,
        "activated_on": today_str()
    })
    supabase.table("licenses").update({
        "machines": machines,
        "last_verified": today_str()
    }).eq("key", key).execute()

    sig = make_signature(key, machine_id, lic.get("expires_on", ""))
    return jsonify({
        "success": True,
        "message": "License activated successfully!",
        "expires": lic.get("expires_on", ""),
        "client_name": lic.get("client_name", ""),
        "days_left": days_left,
        "signature": sig
    })


@app.route("/verify", methods=["POST"])
def verify():
    """
    Called weekly by the app.
    Body: { "key": "...", "machine_id": "..." }
    Response: { "valid": bool, "expires": "...", "days_left": int,
                "message": str, "signature": str }
    """
    data       = request.json or {}
    key        = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "").strip()

    if not key or not machine_id:
        return jsonify({"valid": False, "message": "Missing key or machine ID."}), 400

    resp = supabase.table("licenses").select("*").eq("key", key).execute()
    if not resp.data:
        return jsonify({"valid": False, "message": "License key not found."}), 404

    lic      = resp.data[0]
    machines = lic.get("machines", []) or []
    machine_ids = [m.get("id") for m in machines]

    if machine_id not in machine_ids:
        return jsonify({
            "valid": False,
            "message": "This machine is not registered for this license.\n"
                       "Please activate first or contact KNPP."
        }), 403

    days_left = days_from_today(lic.get("expires_on", ""))
    if days_left < 0:
        return jsonify({
            "valid": False,
            "message": f"License expired on {lic.get('expires_on')}.\n"
                       "Please renew. Contact: Pradip Majumder — 7896489317",
            "expires": lic.get("expires_on", ""),
            "days_left": days_left
        }), 403

    # Update last_verified
    supabase.table("licenses").update({
        "last_verified": today_str()
    }).eq("key", key).execute()

    sig = make_signature(key, machine_id, lic.get("expires_on", ""))
    return jsonify({
        "valid": True,
        "expires": lic.get("expires_on", ""),
        "client_name": lic.get("client_name", ""),
        "days_left": days_left,
        "signature": sig,
        "message": "License valid."
    })


# ── Admin endpoints ─────────────────────────────────────────────

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data        = request.json or {}
    client_name = data.get("client_name", "").strip()
    client_phone = data.get("client_phone", "").strip()
    client_email = data.get("client_email", "").strip()
    max_pcs     = int(data.get("max_pcs", 3))
    notes       = data.get("notes", "")

    if not client_name:
        return jsonify({"success": False, "message": "Client name required."}), 400

    key = generate_key()
    # Activation date = today; expiry = today + 1 year
    activated_on = today_str()
    expires_on   = (date.today() + timedelta(days=365)).isoformat()

    supabase.table("licenses").insert({
        "key":           key,
        "client_name":   client_name,
        "client_phone":  client_phone,
        "client_email":  client_email,
        "max_pcs":       max_pcs,
        "machines":      [],
        "activated_on":  activated_on,
        "expires_on":    expires_on,
        "last_verified": None,
        "status":        "active",
        "notes":         notes
    }).execute()

    return jsonify({
        "success": True,
        "key": key,
        "expires_on": expires_on,
        "message": f"License generated for {client_name}"
    })


@app.route("/admin/licenses", methods=["GET"])
def admin_licenses():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    resp = supabase.table("licenses").select("*").order("activated_on", desc=True).execute()
    licenses = []
    for lic in (resp.data or []):
        days_left = days_from_today(lic.get("expires_on", ""))
        lic["days_left"] = days_left
        if days_left < 0:
            lic["display_status"] = "expired"
        elif days_left <= 30:
            lic["display_status"] = "expiring_soon"
        else:
            lic["display_status"] = "active"
        licenses.append(lic)

    return jsonify({"success": True, "licenses": licenses})


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    resp  = supabase.table("licenses").select("*").execute()
    data  = resp.data or []
    total = len(data)
    active         = sum(1 for l in data if days_from_today(l.get("expires_on","")) >= 30)
    expiring_soon  = sum(1 for l in data if 0 <= days_from_today(l.get("expires_on","")) < 30)
    expired        = sum(1 for l in data if days_from_today(l.get("expires_on","")) < 0)
    total_pcs      = sum(len(l.get("machines", []) or []) for l in data)

    return jsonify({
        "success": True,
        "total": total,
        "active": active,
        "expiring_soon": expiring_soon,
        "expired": expired,
        "total_pcs_activated": total_pcs
    })


@app.route("/admin/renew", methods=["POST"])
def admin_renew():
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json or {}
    key  = data.get("key", "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key required."}), 400

    resp = supabase.table("licenses").select("*").eq("key", key).execute()
    if not resp.data:
        return jsonify({"success": False, "message": "Key not found."}), 404

    lic         = resp.data[0]
    current_exp = lic.get("expires_on", today_str())
    try:
        base = date.fromisoformat(current_exp)
        # If already expired, renew from today; else extend from current expiry
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

    data       = request.json or {}
    key        = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "").strip()

    if not key or not machine_id:
        return jsonify({"success": False, "message": "Key and machine_id required."}), 400

    resp = supabase.table("licenses").select("*").eq("key", key).execute()
    if not resp.data:
        return jsonify({"success": False, "message": "Key not found."}), 404

    lic      = resp.data[0]
    machines = [m for m in (lic.get("machines", []) or []) if m.get("id") != machine_id]

    supabase.table("licenses").update({"machines": machines}).eq("key", key).execute()
    return jsonify({"success": True, "message": "Machine removed. Client can now activate on a new PC."})


@app.route("/admin/revoke_license", methods=["POST"])
def admin_revoke_license():
    """Completely revoke/disable a license"""
    if not check_admin(request):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json or {}
    key  = data.get("key", "").strip().upper()

    supabase.table("licenses").update({
        "status": "revoked",
        "expires_on": "2000-01-01"
    }).eq("key", key).execute()

    return jsonify({"success": True, "message": "License revoked."})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
