# ================================================================
#  admin_panel.py  —  NephroAI Admin Panel  (Blueprint autonome)
#  ──────────────────────────────────────────────────────────────
#  AJOUT MINIMAL : ne modifie rien dans App.py
#  Intégration en 3 lignes dans App.py :
#
#    from admin_panel import admin_bp, init_admin
#    init_admin(get_db, hash_pw)          # juste après init_db()
#    app.register_blueprint(admin_bp)     # avant app.run()
#
#  Route d'accès : http://127.0.0.1:5000/admin
#  Compte admin par défaut : admin / admin2025
# ================================================================

from flask import (Blueprint, request, jsonify, render_template_string,
                   redirect, url_for, make_response)
import sqlite3, secrets, hashlib
from datetime import datetime
from functools import wraps

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# ── Références injectées depuis App.py ────────────────────────
_get_db   = None
_hash_pw  = None
ADMIN_TOKEN_COOKIE = 'nephroai_admin_token'

def init_admin(get_db_fn, hash_pw_fn):
    """Appelé une seule fois depuis App.py après init_db()."""
    global _get_db, _hash_pw
    _get_db  = get_db_fn
    _hash_pw = hash_pw_fn
    _ensure_admin_tables()

# ── Création des tables admin (migration douce) ───────────────
def _ensure_admin_tables():
    conn = _get_db()
    cur  = conn.cursor()

    # Table des comptes admin
    cur.execute("""CREATE TABLE IF NOT EXISTS admin_users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT NOT NULL UNIQUE,
        password   TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")

    # Table des logs d'actions
    cur.execute("""CREATE TABLE IF NOT EXISTS admin_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user  TEXT NOT NULL,
        action      TEXT NOT NULL,
        target_type TEXT,
        target_id   TEXT,
        detail      TEXT,
        ip          TEXT,
        created_at  TEXT NOT NULL
    )""")

    # Table des sessions admin
    cur.execute("""CREATE TABLE IF NOT EXISTS admin_sessions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user TEXT NOT NULL,
        token      TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )""")

    # Compte admin par défaut (admin / admin2025)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cur.execute(
            "INSERT INTO admin_users (username, password, created_at) VALUES (?,?,?)",
            ("admin", _hash_pw("admin2025"), now)
        )
    except sqlite3.IntegrityError:
        pass  # déjà créé

    conn.commit()
    conn.close()

# ── Helpers session admin ─────────────────────────────────────
def _get_admin_from_token(token):
    if not token:
        return None
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute("SELECT admin_user FROM admin_sessions WHERE token=?", (token,))
    row = cur.fetchone()
    conn.close()
    return row["admin_user"] if row else None

def _log(admin_user, action, target_type=None, target_id=None, detail=None):
    conn = _get_db()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip   = request.remote_addr
    conn.execute(
        "INSERT INTO admin_logs (admin_user,action,target_type,target_id,detail,ip,created_at) VALUES (?,?,?,?,?,?,?)",
        (admin_user, action, target_type, str(target_id) if target_id else None, detail, ip, now)
    )
    conn.commit()
    conn.close()

def require_admin(f):
    """Décorateur : protège les routes admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get(ADMIN_TOKEN_COOKIE)
        admin = _get_admin_from_token(token)
        if not admin:
            if request.path.startswith('/admin/api/'):
                return jsonify({"success": False, "error": "Non authentifié"}), 401
            return redirect(url_for('admin.login_page'))
        request.admin_user = admin
        return f(*args, **kwargs)
    return decorated

# ================================================================
#  ROUTES AUTH ADMIN
# ================================================================
@admin_bp.route('/login', methods=['GET'])
def login_page():
    return render_template_string(_ADMIN_HTML)

@admin_bp.route('/login', methods=['POST'])
def do_login():
    data = request.get_json(force=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({"success": False, "error": "Champs requis"}), 400

    conn = _get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id FROM admin_users WHERE username=? AND password=?",
        (username, _hash_pw(password))
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Identifiants incorrects"}), 401

    token = secrets.token_hex(32)
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO admin_sessions (admin_user, token, created_at) VALUES (?,?,?)",
        (username, token, now)
    )
    conn.commit()
    conn.close()

    _log(username, "LOGIN", detail=f"Connexion depuis {request.remote_addr}")
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie(ADMIN_TOKEN_COOKIE, token, httponly=True, samesite='Lax', max_age=86400)
    return resp

@admin_bp.route('/logout', methods=['POST'])
@require_admin
def do_logout():
    token = request.cookies.get(ADMIN_TOKEN_COOKIE)
    _log(request.admin_user, "LOGOUT")
    conn = _get_db()
    conn.execute("DELETE FROM admin_sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
    resp = make_response(jsonify({"success": True}))
    resp.delete_cookie(ADMIN_TOKEN_COOKIE)
    return resp

@admin_bp.route('/')
@require_admin
def dashboard():
    return render_template_string(_ADMIN_HTML)

# ================================================================
#  API — STATISTIQUES
# ================================================================
@admin_bp.route('/api/stats')
@require_admin
def api_stats():
    conn = _get_db()
    cur  = conn.cursor()
    total_users  = cur.execute("SELECT COUNT(*) as n FROM users").fetchone()["n"]
    medecins     = cur.execute("SELECT COUNT(*) as n FROM users WHERE role='medecin'").fetchone()["n"]
    patients     = cur.execute("SELECT COUNT(*) as n FROM users WHERE role='patient'").fetchone()["n"]
    predictions  = cur.execute("SELECT COUNT(*) as n FROM predictions").fetchone()["n"]
    high_risk    = cur.execute("SELECT COUNT(*) as n FROM predictions WHERE risk_level='high'").fetchone()["n"]
    subscriptions= cur.execute("SELECT COUNT(*) as n FROM subscriptions WHERE status='active'").fetchone()["n"]
    last_24h     = cur.execute(
        "SELECT COUNT(*) as n FROM predictions WHERE predicted_at >= datetime('now','-1 day')"
    ).fetchone()["n"]
    conn.close()
    return jsonify({
        "success": True,
        "stats": {
            "total_users":   total_users,
            "medecins":      medecins,
            "patients":      patients,
            "predictions":   predictions,
            "high_risk":     high_risk,
            "subscriptions": subscriptions,
            "last_24h":      last_24h,
        }
    })

# ================================================================
#  API — UTILISATEURS (CRUD)
# ================================================================
@admin_bp.route('/api/users')
@require_admin
def api_users():
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.email, u.nom, u.prenom, u.role, u.created_at,
               COUNT(p.id) as pred_count
        FROM users u
        LEFT JOIN patients pt ON pt.user_id = u.id OR pt.doctor_id = u.id
        LEFT JOIN predictions p ON p.patient_id = pt.id
        GROUP BY u.id
        ORDER BY u.id DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "users": rows, "total": len(rows)})

@admin_bp.route('/api/users/<int:uid>', methods=['GET'])
@require_admin
def api_user_detail(uid):
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id,username,email,nom,prenom,role,created_at,phone,wilaya,etablissement,specialite FROM users WHERE id=?", (uid,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "error": "Utilisateur introuvable"}), 404
    cur.execute("SELECT COUNT(*) as n FROM predictions pr JOIN patients pt ON pt.id=pr.patient_id WHERE pt.doctor_id=? OR pt.user_id=?", (uid, uid))
    pred_count = cur.fetchone()["n"]
    cur.execute("SELECT risk_level, percentage, predicted_at FROM predictions pr JOIN patients pt ON pt.id=pr.patient_id WHERE pt.doctor_id=? OR pt.user_id=? ORDER BY pr.predicted_at DESC LIMIT 5", (uid, uid))
    recent = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "user": dict(user), "pred_count": pred_count, "recent_predictions": recent})

@admin_bp.route('/api/users', methods=['POST'])
@require_admin
def api_create_user():
    data     = request.get_json(force=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role     = data.get('role', 'patient').strip()
    nom      = data.get('nom', '').strip()
    prenom   = data.get('prenom', '').strip()
    email    = data.get('email', '').strip() or None
    if not username or not password or role not in ('medecin', 'patient'):
        return jsonify({"success": False, "error": "Données invalides"}), 400
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = _get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (username,email,password,role,nom,prenom,created_at) VALUES (?,?,?,?,?,?,?)",
            (username, email, _hash_pw(password), role, nom, prenom, now)
        )
        new_id = cur.lastrowid
        conn.commit()
        conn.close()
        _log(request.admin_user, "CREATE_USER", "user", new_id, f"{role} @{username}")
        return jsonify({"success": True, "user_id": new_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Nom d'utilisateur déjà pris"}), 409

@admin_bp.route('/api/users/<int:uid>', methods=['PUT'])
@require_admin
def api_update_user(uid):
    data    = request.get_json(force=True) or {}
    allowed = ['nom', 'prenom', 'email', 'role', 'phone', 'wilaya', 'etablissement', 'specialite']
    updates = {k: data[k] for k in allowed if k in data}
    new_pw  = data.get('new_password', '').strip()
    if new_pw:
        if len(new_pw) < 6:
            return jsonify({"success": False, "error": "Mot de passe trop court"}), 400
        updates['password'] = _hash_pw(new_pw)
    if not updates:
        return jsonify({"success": False, "error": "Rien à mettre à jour"}), 400
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id=?", (uid,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Utilisateur introuvable"}), 404
    set_clause = ", ".join(f"{k}=?" for k in updates)
    conn.execute(f"UPDATE users SET {set_clause} WHERE id=?", list(updates.values()) + [uid])
    conn.commit()
    conn.close()
    _log(request.admin_user, "UPDATE_USER", "user", uid, str(list(updates.keys())))
    return jsonify({"success": True, "updated": list(updates.keys())})

@admin_bp.route('/api/users/<int:uid>', methods=['DELETE'])
@require_admin
def api_delete_user(uid):
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute("SELECT username, role FROM users WHERE id=?", (uid,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Utilisateur introuvable"}), 404
    # Cascade : prédictions → patients → tokens → user
    cur.execute("DELETE FROM predictions WHERE patient_id IN (SELECT id FROM patients WHERE user_id=? OR doctor_id=?)", (uid, uid))
    cur.execute("DELETE FROM patients WHERE user_id=? OR doctor_id=?", (uid, uid))
    cur.execute("DELETE FROM tokens WHERE user_id=?", (uid,))
    cur.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    _log(request.admin_user, "DELETE_USER", "user", uid, f"@{row['username']} ({row['role']})")
    return jsonify({"success": True, "deleted_id": uid})

# ================================================================
#  API — LOGS
# ================================================================
@admin_bp.route('/api/logs')
@require_admin
def api_logs():
    limit  = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    rows  = [dict(r) for r in cur.fetchall()]
    total = conn.execute("SELECT COUNT(*) as n FROM admin_logs").fetchone()["n"]
    conn.close()
    return jsonify({"success": True, "logs": rows, "total": total})

# ================================================================
#  API — ADMINS (gestion des comptes admin)
# ================================================================
@admin_bp.route('/api/admins')
@require_admin
def api_admins():
    conn = _get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, username, created_at FROM admin_users ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"success": True, "admins": rows})

@admin_bp.route('/api/admins', methods=['POST'])
@require_admin
def api_create_admin():
    data = request.get_json(force=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password or len(password) < 6:
        return jsonify({"success": False, "error": "Username et mot de passe (6 car. min.) requis"}), 400
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = _get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO admin_users (username, password, created_at) VALUES (?,?,?)",
            (username, _hash_pw(password), now)
        )
        new_id = cur.lastrowid
        conn.commit()
        conn.close()
        _log(request.admin_user, "CREATE_ADMIN", "admin", new_id, f"@{username}")
        return jsonify({"success": True, "admin_id": new_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Ce nom d'admin est déjà pris"}), 409

@admin_bp.route('/api/admins/<int:aid>', methods=['DELETE'])
@require_admin
def api_delete_admin(aid):
    conn = _get_db()
    cur  = conn.cursor()
    # Empêcher la suppression du dernier admin
    total = conn.execute("SELECT COUNT(*) as n FROM admin_users").fetchone()["n"]
    if total <= 1:
        conn.close()
        return jsonify({"success": False, "error": "Impossible de supprimer le dernier admin"}), 400
    cur.execute("SELECT username FROM admin_users WHERE id=?", (aid,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Admin introuvable"}), 404
    cur.execute("DELETE FROM admin_sessions WHERE admin_user=?", (row["username"],))
    cur.execute("DELETE FROM admin_users WHERE id=?", (aid,))
    conn.commit()
    conn.close()
    _log(request.admin_user, "DELETE_ADMIN", "admin", aid, f"@{row['username']}")
    return jsonify({"success": True, "deleted_id": aid})

# ================================================================
#  API — WHO AM I
# ================================================================
@admin_bp.route('/api/me')
@require_admin
def api_me():
    return jsonify({"success": True, "admin": request.admin_user})

# ================================================================
#  HTML TEMPLATE (single-file SPA)
# ================================================================
_ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>NephroAI — Admin Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --navy:#0B1628;--navy2:#111E35;--navy3:#192844;
  --blue:#2563EB;--cyan:#06B6D4;--emerald:#10B981;
  --amber:#F59E0B;--rose:#F43F5E;--violet:#7C3AED;
  --surface:#fff;--surface2:#F8FAFC;--border:#E2E8F0;
  --text:#0F172A;--muted:#64748B;--light:#94A3B8;
  --sidebar-w:240px;
}
body{font-family:'Sora',system-ui,sans-serif;background:var(--surface2);color:var(--text);font-size:13.5px;min-height:100vh}

/* ── LOGIN ── */
#loginScreen{position:fixed;inset:0;z-index:9999;background:var(--navy);display:flex;align-items:center;justify-content:center}
#loginScreen.hidden{display:none}
.login-bg{position:absolute;inset:0;background:radial-gradient(ellipse 60% 50% at 20% 80%,rgba(37,99,235,.2),transparent 60%),radial-gradient(ellipse 50% 40% at 80% 20%,rgba(124,58,237,.15),transparent 60%)}
.login-box{position:relative;z-index:2;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px;padding:2.5rem;width:100%;max-width:380px;backdrop-filter:blur(20px)}
.login-logo{width:44px;height:44px;background:linear-gradient(135deg,var(--blue),var(--cyan));border-radius:12px;display:flex;align-items:center;justify-content:center;margin-bottom:1.25rem}
.login-logo svg{width:22px;height:22px;stroke:#fff;fill:none;stroke-width:2.5}
.login-box h1{font-size:1.4rem;font-weight:700;color:#fff;margin-bottom:.25rem}
.login-box p{font-size:.78rem;color:rgba(255,255,255,.4);margin-bottom:1.75rem}
.lf{margin-bottom:.875rem}
.lf label{display:block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:rgba(255,255,255,.35);margin-bottom:.35rem}
.lf input{width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:9px;padding:10px 13px;font-size:.88rem;font-family:inherit;color:#fff;outline:none;transition:.2s}
.lf input:focus{border-color:var(--cyan);background:rgba(255,255,255,.09);box-shadow:0 0 0 3px rgba(6,182,212,.15)}
.lf input::placeholder{color:rgba(255,255,255,.2)}
.login-btn{width:100%;background:linear-gradient(135deg,var(--blue),#1D4ED8);border:none;border-radius:9px;padding:11px;font-size:.9rem;font-weight:700;color:#fff;cursor:pointer;font-family:inherit;box-shadow:0 4px 20px rgba(37,99,235,.4);transition:.2s;margin-top:.25rem}
.login-btn:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(37,99,235,.5)}
.login-btn:disabled{opacity:.5;cursor:wait;transform:none}
.login-err{margin-top:.75rem;padding:.6rem .9rem;background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.3);border-radius:8px;font-size:.78rem;color:#FDA4AF;display:none}
.login-hint{margin-top:1rem;font-size:.73rem;color:rgba(255,255,255,.25);text-align:center}
.login-hint strong{color:rgba(255,255,255,.4)}

/* ── APP SHELL ── */
#app{display:none;min-height:100vh}
#app.visible{display:flex}

/* ── SIDEBAR ── */
.sidebar{width:var(--sidebar-w);background:var(--navy);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:100;overflow-y:auto}
.sidebar-logo{display:flex;align-items:center;gap:9px;padding:1.25rem 1.1rem;border-bottom:1px solid rgba(255,255,255,.07)}
.sidebar-logo-icon{width:28px;height:28px;background:linear-gradient(135deg,var(--blue),var(--cyan));border-radius:7px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sidebar-logo-icon svg{width:14px;height:14px;stroke:#fff;fill:none;stroke-width:2.5}
.sidebar-logo-text{font-size:.88rem;font-weight:700;color:#fff;line-height:1.2}
.sidebar-logo-text small{display:block;font-size:.62rem;font-weight:400;color:rgba(255,255,255,.35);letter-spacing:.05em;text-transform:uppercase}
.sidebar-admin-chip{margin:.75rem 1rem;background:rgba(124,58,237,.2);border:1px solid rgba(124,58,237,.3);border-radius:8px;padding:.5rem .75rem;font-size:.73rem;color:#C4B5FD;font-weight:600;display:flex;align-items:center;gap:6px}
.sidebar-admin-chip::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--emerald);flex-shrink:0}
.sidebar-nav{padding:.5rem .6rem;flex:1}
.nav-section{font-size:.63rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.25);padding:.75rem .5rem .35rem;margin-top:.25rem}
.nav-btn{display:flex;align-items:center;gap:9px;width:100%;background:transparent;border:none;border-radius:9px;padding:.65rem .85rem;color:rgba(255,255,255,.45);font-size:.8rem;font-weight:500;font-family:inherit;cursor:pointer;transition:.15s;text-align:left}
.nav-btn svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;flex-shrink:0;opacity:.7}
.nav-btn:hover{background:rgba(255,255,255,.07);color:rgba(255,255,255,.8)}
.nav-btn.active{background:rgba(37,99,235,.2);color:#93C5FD;border:1px solid rgba(37,99,235,.3)}
.nav-btn.active svg{opacity:1}
.sidebar-footer{padding:.75rem .6rem 1rem;border-top:1px solid rgba(255,255,255,.07)}
.logout-btn{display:flex;align-items:center;gap:8px;width:100%;background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.15);border-radius:8px;padding:.6rem .85rem;color:rgba(244,63,94,.7);font-size:.78rem;font-weight:600;font-family:inherit;cursor:pointer;transition:.15s}
.logout-btn:hover{background:rgba(244,63,94,.15);color:#FDA4AF}
.logout-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2}

/* ── MAIN ── */
.main{margin-left:var(--sidebar-w);flex:1;display:flex;flex-direction:column;min-height:100vh}

/* ── TOPBAR ── */
.topbar{height:56px;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 1.5rem;gap:1rem;position:sticky;top:0;z-index:50}
.topbar h2{font-size:.95rem;font-weight:700;color:var(--text);flex:1}
.topbar-badge{background:rgba(37,99,235,.08);border:1px solid rgba(37,99,235,.2);color:var(--blue);border-radius:6px;padding:3px 10px;font-size:.7rem;font-weight:700;letter-spacing:.06em}

/* ── CONTENT ── */
.content{padding:1.5rem;flex:1}
.page{display:none;animation:fadeIn .2s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

/* ── STAT CARDS ── */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
@media(max-width:900px){.stats-grid{grid-template-columns:1fr 1fr}}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.1rem 1.25rem;display:flex;align-items:flex-start;gap:.875rem}
.stat-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;flex-shrink:0}
.stat-num{font-size:1.8rem;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1;margin-bottom:2px}
.stat-lbl{font-size:.72rem;color:var(--muted);font-weight:500}
.ic-blue{background:rgba(37,99,235,.1);color:var(--blue)}
.ic-emerald{background:rgba(16,185,129,.1);color:var(--emerald)}
.ic-amber{background:rgba(245,158,11,.1);color:var(--amber)}
.ic-rose{background:rgba(244,63,94,.1);color:var(--rose)}
.ic-violet{background:rgba(124,58,237,.1);color:var(--violet)}
.ic-cyan{background:rgba(6,182,212,.1);color:var(--cyan)}

/* ── CARDS ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;margin-bottom:1.25rem}
.card-head{padding:1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.card-head h3{font-size:.9rem;font-weight:700}
.card-body{padding:1.25rem}

/* ── TABLE ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
thead tr{background:var(--surface2)}
th{padding:9px 14px;text-align:left;font-size:.7rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--light)}
td{padding:11px 14px;font-size:.83rem;border-top:1px solid var(--border)}
tr:hover td{background:var(--surface2)}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:.7rem;font-weight:700}
.badge.medecin{background:#EDE9FE;color:#6D28D9}
.badge.patient{background:#E0F2FE;color:#0369A1}
.badge.admin{background:#FEE2E2;color:#991B1B}
.badge.active{background:#D1FAE5;color:#065F46}
.badge.inactive{background:#F1F5F9;color:#64748B}

/* ── BUTTONS ── */
.btn{border:none;border-radius:8px;padding:7px 14px;font-size:.78rem;font-weight:700;font-family:inherit;cursor:pointer;transition:.15s;display:inline-flex;align-items:center;gap:5px}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:#1D4ED8}
.btn-danger{background:rgba(244,63,94,.1);color:var(--rose);border:1px solid rgba(244,63,94,.2)}
.btn-danger:hover{background:rgba(244,63,94,.18)}
.btn-secondary{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--border);color:var(--text)}
.btn-sm{padding:4px 10px;font-size:.72rem}

/* ── SEARCH ── */
.search-wrap{position:relative;display:inline-flex;align-items:center}
.search-wrap svg{position:absolute;left:9px;width:13px;height:13px;stroke:var(--light);fill:none;stroke-width:2;pointer-events:none}
.search-input{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:7px 11px 7px 30px;font-size:.8rem;font-family:inherit;color:var(--text);width:220px;outline:none;transition:.15s}
.search-input:focus{border-color:var(--blue);background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,.1)}

/* ── MODAL ── */
.modal-overlay{position:fixed;inset:0;z-index:8000;background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center;padding:1rem;backdrop-filter:blur(4px)}
.modal-overlay.hidden{display:none}
.modal{background:var(--surface);border-radius:16px;width:100%;max-width:480px;box-shadow:0 20px 60px rgba(0,0,0,.2);animation:fadeIn .2s ease}
.modal-head{padding:1.1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.modal-head h3{font-size:.95rem;font-weight:700}
.modal-close{background:none;border:none;cursor:pointer;color:var(--light);font-size:1.2rem;line-height:1}
.modal-body{padding:1.25rem}
.mf{margin-bottom:.875rem}
.mf label{display:block;font-size:.73rem;font-weight:600;color:var(--muted);margin-bottom:.3rem}
.mf input,.mf select{width:100%;background:var(--surface2);border:1.5px solid var(--border);border-radius:9px;padding:9px 12px;font-size:.86rem;font-family:inherit;color:var(--text);outline:none;transition:.15s}
.mf input:focus,.mf select:focus{border-color:var(--blue);background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.mf-grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
.mf-actions{display:flex;gap:.75rem;margin-top:1rem}
.mf-msg{margin-top:.6rem;font-size:.78rem;text-align:center}

/* ── LOGS ── */
.log-item{display:flex;align-items:flex-start;gap:.75rem;padding:.7rem 0;border-bottom:1px solid var(--border)}
.log-item:last-child{border-bottom:none}
.log-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:5px}
.log-action{font-size:.82rem;font-weight:600;color:var(--text)}
.log-detail{font-size:.75rem;color:var(--muted);margin-top:2px}
.log-time{font-size:.7rem;color:var(--light);white-space:nowrap;font-family:'JetBrains Mono',monospace;margin-left:auto;flex-shrink:0}

/* ── ACTION COLOURS ── */
.dot-login    {background:var(--emerald)}
.dot-logout   {background:var(--light)}
.dot-create   {background:var(--blue)}
.dot-update   {background:var(--amber)}
.dot-delete   {background:var(--rose)}

/* ── EMPTY / TOAST ── */
.empty{text-align:center;padding:3rem;color:var(--light);font-size:.85rem}
.toast{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;background:var(--navy);color:#fff;padding:.75rem 1.25rem;border-radius:10px;font-size:.82rem;font-weight:600;box-shadow:0 8px 30px rgba(0,0,0,.3);animation:fadeIn .2s ease;display:none}
.toast.show{display:block}
.toast.ok{border-left:3px solid var(--emerald)}
.toast.err{border-left:3px solid var(--rose)}

/* ── DETAIL PANEL ── */
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}
.di{background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:.65rem .85rem}
.di .dk{font-size:.68rem;color:var(--light);font-weight:700;margin-bottom:2px;text-transform:uppercase;letter-spacing:.05em}
.di .dv{font-size:.85rem;font-weight:700;color:var(--text);font-family:'JetBrains Mono',monospace}
</style>
</head>
<body>

<!-- ══ LOGIN ══ -->
<div id="loginScreen">
  <div class="login-bg"></div>
  <div class="login-box">
    <div class="login-logo"><svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div>
    <h1>NephroAI Admin</h1>
    <p>Panneau d'administration — accès restreint</p>
    <div class="lf"><label>Identifiant</label><input type="text" id="loginUser" placeholder="admin" autocomplete="username"/></div>
    <div class="lf"><label>Mot de passe</label><input type="password" id="loginPass" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"/></div>
    <button class="login-btn" id="loginBtn" onclick="doLogin()">Connexion</button>
    <div class="login-err" id="loginErr"></div>
    <p class="login-hint">Compte par défaut : <strong>admin</strong> / <strong>admin2025</strong></p>
  </div>
</div>

<!-- ══ MODALS ══ -->
<!-- User modal -->
<div id="userModal" class="modal-overlay hidden">
  <div class="modal">
    <div class="modal-head">
      <h3 id="userModalTitle">Utilisateur</h3>
      <button class="modal-close" onclick="closeModal('userModal')">×</button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="umId"/>
      <div class="mf-grid">
        <div class="mf"><label>Prénom</label><input type="text" id="umPrenom"/></div>
        <div class="mf"><label>Nom</label><input type="text" id="umNom"/></div>
      </div>
      <div class="mf"><label>Nom d'utilisateur *</label><input type="text" id="umUsername"/></div>
      <div class="mf"><label>Email</label><input type="email" id="umEmail"/></div>
      <div class="mf"><label>Rôle</label>
        <select id="umRole">
          <option value="patient">Patient</option>
          <option value="medecin">Médecin</option>
        </select>
      </div>
      <div class="mf"><label id="pwLabel">Mot de passe *</label><input type="password" id="umPwd" placeholder="••••••••"/></div>
      <div class="mf-actions">
        <button class="btn btn-primary" onclick="saveUser()" style="flex:1">Enregistrer</button>
        <button class="btn btn-secondary" onclick="closeModal('userModal')">Annuler</button>
      </div>
      <div class="mf-msg" id="umMsg"></div>
    </div>
  </div>
</div>

<!-- Admin modal -->
<div id="adminModal" class="modal-overlay hidden">
  <div class="modal">
    <div class="modal-head">
      <h3>Nouvel administrateur</h3>
      <button class="modal-close" onclick="closeModal('adminModal')">×</button>
    </div>
    <div class="modal-body">
      <div class="mf"><label>Nom d'utilisateur *</label><input type="text" id="amUsername"/></div>
      <div class="mf"><label>Mot de passe * (6 car. min.)</label><input type="password" id="amPwd"/></div>
      <div class="mf-actions">
        <button class="btn btn-primary" onclick="saveAdmin()" style="flex:1">Créer l'admin</button>
        <button class="btn btn-secondary" onclick="closeModal('adminModal')">Annuler</button>
      </div>
      <div class="mf-msg" id="amMsg"></div>
    </div>
  </div>
</div>

<!-- User detail modal -->
<div id="detailModal" class="modal-overlay hidden">
  <div class="modal" style="max-width:540px">
    <div class="modal-head">
      <h3 id="detailTitle">Détail utilisateur</h3>
      <button class="modal-close" onclick="closeModal('detailModal')">×</button>
    </div>
    <div class="modal-body" id="detailBody"></div>
  </div>
</div>

<!-- ══ APP ══ -->
<div id="app">
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon"><svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div>
      <div class="sidebar-logo-text">NephroAI<small>Admin Panel</small></div>
    </div>
    <div class="sidebar-admin-chip" id="adminChip">admin</div>
    <nav class="sidebar-nav">
      <div class="nav-section">Navigation</div>
      <button class="nav-btn active" data-page="dashboard" onclick="showPage('dashboard',this)">
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        Tableau de bord
      </button>
      <button class="nav-btn" data-page="users" onclick="showPage('users',this)">
        <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        Utilisateurs
      </button>
      <button class="nav-btn" data-page="logs" onclick="showPage('logs',this)">
        <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
        Logs d'actions
      </button>
      <button class="nav-btn" data-page="admins" onclick="showPage('admins',this)">
        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Comptes Admin
      </button>
    </nav>
    <div class="sidebar-footer">
      <button class="logout-btn" onclick="doLogout()">
        <svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Déconnexion
      </button>
    </div>
  </aside>

  <!-- Main -->
  <div class="main">
    <div class="topbar">
      <h2 id="topbarTitle">Tableau de bord</h2>
      <span class="topbar-badge">ADMIN</span>
    </div>
    <div class="content">

      <!-- ── DASHBOARD ── -->
      <div id="page-dashboard" class="page active">
        <div class="stats-grid" id="statsGrid">
          <div class="stat-card"><div class="stat-icon ic-blue">👥</div><div><div class="stat-num" id="s-total">—</div><div class="stat-lbl">Utilisateurs total</div></div></div>
          <div class="stat-card"><div class="stat-icon ic-violet">🩺</div><div><div class="stat-num" id="s-med">—</div><div class="stat-lbl">Médecins</div></div></div>
          <div class="stat-card"><div class="stat-icon ic-cyan">🧑</div><div><div class="stat-num" id="s-pat">—</div><div class="stat-lbl">Patients</div></div></div>
          <div class="stat-card"><div class="stat-icon ic-emerald">📊</div><div><div class="stat-num" id="s-pred">—</div><div class="stat-lbl">Prédictions totales</div></div></div>
          <div class="stat-card"><div class="stat-icon ic-rose">⚠️</div><div><div class="stat-num" id="s-high">—</div><div class="stat-lbl">Risque élevé</div></div></div>
          <div class="stat-card"><div class="stat-icon ic-amber">💳</div><div><div class="stat-num" id="s-sub">—</div><div class="stat-lbl">Abonnements actifs</div></div></div>
          <div class="stat-card"><div class="stat-icon ic-blue">🕐</div><div><div class="stat-num" id="s-24h">—</div><div class="stat-lbl">Prédictions 24h</div></div></div>
        </div>
        <div class="card">
          <div class="card-head"><h3>📋 Dernières actions</h3><button class="btn btn-secondary btn-sm" onclick="showPage('logs',document.querySelector('[data-page=logs]'))">Voir tout →</button></div>
          <div class="card-body" id="dashLogs"><div class="empty">Chargement…</div></div>
        </div>
      </div>

      <!-- ── USERS ── -->
      <div id="page-users" class="page">
        <div class="card">
          <div class="card-head">
            <h3>👥 Gestion des utilisateurs</h3>
            <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">
              <div class="search-wrap">
                <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                <input class="search-input" id="userSearch" placeholder="Rechercher…" oninput="filterUsers()"/>
              </div>
              <button class="btn btn-primary btn-sm" onclick="openCreateUser()">+ Ajouter</button>
            </div>
          </div>
          <div class="tbl-wrap" id="usersTableWrap"><div class="empty">Chargement…</div></div>
        </div>
      </div>

      <!-- ── LOGS ── -->
      <div id="page-logs" class="page">
        <div class="card">
          <div class="card-head">
            <h3>📋 Historique des actions</h3>
            <button class="btn btn-secondary btn-sm" onclick="loadLogs()">↻ Actualiser</button>
          </div>
          <div class="card-body" id="logsWrap"><div class="empty">Chargement…</div></div>
        </div>
      </div>

      <!-- ── ADMINS ── -->
      <div id="page-admins" class="page">
        <div class="card">
          <div class="card-head">
            <h3>🛡 Comptes administrateurs</h3>
            <button class="btn btn-primary btn-sm" onclick="openModal('adminModal');document.getElementById('amUsername').value='';document.getElementById('amPwd').value=''">+ Nouvel admin</button>
          </div>
          <div class="tbl-wrap" id="adminsTableWrap"><div class="empty">Chargement…</div></div>
        </div>
      </div>

    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
const API = '/admin/api';
let allUsers = [];
let currentAdmin = null;

// ── Toast ──────────────────────────────────────────────
function toast(msg, type='ok') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast show ${type}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3000);
}

// ── Modal ──────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }
document.querySelectorAll('.modal-overlay').forEach(o => {
  o.addEventListener('click', e => { if(e.target===o) o.classList.add('hidden'); });
});

// ── Navigation ─────────────────────────────────────────
const PAGE_TITLES = {dashboard:'Tableau de bord', users:'Utilisateurs', logs:'Logs d\'actions', admins:'Comptes Admin'};
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  document.getElementById('topbarTitle').textContent = PAGE_TITLES[id] || id;
  if(id==='users')  loadUsers();
  if(id==='logs')   loadLogs();
  if(id==='admins') loadAdmins();
}

// ── Auth ───────────────────────────────────────────────
async function doLogin() {
  const btn  = document.getElementById('loginBtn');
  const user = document.getElementById('loginUser').value.trim();
  const pass = document.getElementById('loginPass').value;
  if(!user||!pass) { showErr('Champs requis.'); return; }
  btn.disabled = true; btn.textContent = 'Connexion…';
  try {
    const r = await fetch(`${API.replace('/api','')}/login`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username:user, password:pass})
    });
    const d = await r.json();
    if(d.success) { enterApp(); }
    else          { showErr(d.error||'Identifiants incorrects.'); }
  } catch { showErr('Serveur indisponible.'); }
  btn.disabled = false; btn.textContent = 'Connexion';
}
function showErr(msg) {
  const e = document.getElementById('loginErr');
  e.textContent = msg; e.style.display = 'block';
}

async function enterApp() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('app').classList.add('visible');
  // get admin name
  try {
    const r = await fetch(`${API}/me`);
    const d = await r.json();
    if(d.success) {
      currentAdmin = d.admin;
      document.getElementById('adminChip').textContent = '⚡ ' + d.admin;
    }
  } catch {}
  loadStats();
  loadDashLogs();
}

async function doLogout() {
  try { await fetch(`${API.replace('/api','')}/logout`, {method:'POST'}); } catch {}
  document.getElementById('app').classList.remove('visible');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('loginErr').style.display = 'none';
}

// ── Stats ──────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch(`${API}/stats`);
    const d = await r.json();
    if(!d.success) return;
    const s = d.stats;
    document.getElementById('s-total').textContent = s.total_users;
    document.getElementById('s-med').textContent   = s.medecins;
    document.getElementById('s-pat').textContent   = s.patients;
    document.getElementById('s-pred').textContent  = s.predictions;
    document.getElementById('s-high').textContent  = s.high_risk;
    document.getElementById('s-sub').textContent   = s.subscriptions;
    document.getElementById('s-24h').textContent   = s.last_24h;
  } catch {}
}

// ── Dash logs ──────────────────────────────────────────
async function loadDashLogs() {
  try {
    const r = await fetch(`${API}/logs?limit=8`);
    const d = await r.json();
    const wrap = document.getElementById('dashLogs');
    if(!d.success || !d.logs.length) { wrap.innerHTML = '<div class="empty">Aucune action enregistrée.</div>'; return; }
    wrap.innerHTML = d.logs.map(renderLogItem).join('');
  } catch {}
}

function renderLogItem(l) {
  const dotCls = l.action.startsWith('LOGIN')?'dot-login':l.action.startsWith('LOGOUT')?'dot-logout':l.action.startsWith('CREATE')?'dot-create':l.action.startsWith('UPDATE')?'dot-update':'dot-delete';
  const detail = [l.target_type, l.target_id ? '#'+l.target_id : '', l.detail].filter(Boolean).join(' · ');
  return `<div class="log-item">
    <div class="log-dot ${dotCls}"></div>
    <div style="flex:1;min-width:0">
      <div class="log-action">${l.admin_user} — ${l.action}</div>
      <div class="log-detail">${detail || '—'} · IP ${l.ip||'—'}</div>
    </div>
    <div class="log-time">${(l.created_at||'').slice(0,16)}</div>
  </div>`;
}

// ── Logs page ──────────────────────────────────────────
async function loadLogs() {
  const wrap = document.getElementById('logsWrap');
  wrap.innerHTML = '<div class="empty">Chargement…</div>';
  try {
    const r = await fetch(`${API}/logs?limit=200`);
    const d = await r.json();
    if(!d.success || !d.logs.length) { wrap.innerHTML = '<div class="empty">Aucun log.</div>'; return; }
    wrap.innerHTML = d.logs.map(renderLogItem).join('');
  } catch { wrap.innerHTML = '<div class="empty">Erreur de chargement.</div>'; }
}

// ── Users ──────────────────────────────────────────────
async function loadUsers() {
  const wrap = document.getElementById('usersTableWrap');
  wrap.innerHTML = '<div class="empty">Chargement…</div>';
  try {
    const r = await fetch(`${API}/users`);
    const d = await r.json();
    if(!d.success) throw new Error();
    allUsers = d.users;
    renderUsersTable(allUsers);
  } catch { wrap.innerHTML = '<div class="empty">Erreur de chargement.</div>'; }
}

function filterUsers() {
  const q = document.getElementById('userSearch').value.toLowerCase();
  renderUsersTable(q ? allUsers.filter(u =>
    (u.username||'').toLowerCase().includes(q) ||
    (u.nom||'').toLowerCase().includes(q) ||
    (u.prenom||'').toLowerCase().includes(q) ||
    (u.email||'').toLowerCase().includes(q)
  ) : allUsers);
}

function renderUsersTable(users) {
  const wrap = document.getElementById('usersTableWrap');
  if(!users.length) { wrap.innerHTML = '<div class="empty">Aucun utilisateur.</div>'; return; }
  wrap.innerHTML = `<table>
    <thead><tr><th>ID</th><th>Utilisateur</th><th>Nom complet</th><th>Email</th><th>Rôle</th><th>Prédictions</th><th>Créé le</th><th>Actions</th></tr></thead>
    <tbody>${users.map(u => `<tr>
      <td><span style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--muted)">#${u.id}</span></td>
      <td><strong>@${u.username}</strong></td>
      <td>${[u.prenom,u.nom].filter(Boolean).join(' ')||'—'}</td>
      <td style="font-size:.78rem;color:var(--muted)">${u.email||'—'}</td>
      <td><span class="badge ${u.role}">${u.role}</span></td>
      <td><span style="font-family:'JetBrains Mono',monospace">${u.pred_count||0}</span></td>
      <td style="font-size:.75rem;color:var(--muted)">${(u.created_at||'').slice(0,10)}</td>
      <td>
        <div style="display:flex;gap:.3rem;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm" onclick="openUserDetail(${u.id})">👁</button>
          <button class="btn btn-secondary btn-sm" onclick="openEditUser(${u.id})">✏️</button>
          <button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id},'${u.username}')">🗑</button>
        </div>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

function openCreateUser() {
  document.getElementById('userModalTitle').textContent = 'Créer un utilisateur';
  document.getElementById('pwLabel').textContent = 'Mot de passe *';
  ['umId','umPrenom','umNom','umUsername','umEmail','umPwd'].forEach(id => { const e=document.getElementById(id); if(e) e.value=''; });
  document.getElementById('umRole').value = 'patient';
  document.getElementById('umMsg').innerHTML = '';
  openModal('userModal');
}

function openEditUser(id) {
  const u = allUsers.find(x => x.id === id);
  if(!u) return;
  document.getElementById('userModalTitle').textContent = 'Modifier @' + u.username;
  document.getElementById('pwLabel').textContent = 'Nouveau mot de passe (vide = inchangé)';
  document.getElementById('umId').value       = u.id;
  document.getElementById('umPrenom').value   = u.prenom  || '';
  document.getElementById('umNom').value      = u.nom     || '';
  document.getElementById('umUsername').value = u.username;
  document.getElementById('umEmail').value    = u.email   || '';
  document.getElementById('umRole').value     = u.role;
  document.getElementById('umPwd').value      = '';
  document.getElementById('umMsg').innerHTML  = '';
  openModal('userModal');
}

async function saveUser() {
  const id     = document.getElementById('umId').value;
  const uname  = document.getElementById('umUsername').value.trim();
  const pwd    = document.getElementById('umPwd').value;
  const nom    = document.getElementById('umNom').value.trim();
  const prenom = document.getElementById('umPrenom').value.trim();
  const email  = document.getElementById('umEmail').value.trim();
  const role   = document.getElementById('umRole').value;
  const msgEl  = document.getElementById('umMsg');
  msgEl.innerHTML = '';

  if(!uname) { msgEl.innerHTML = '<span style="color:var(--rose)">Nom d\'utilisateur requis.</span>'; return; }

  let url, method, body;
  if(id) {
    url = `${API}/users/${id}`; method = 'PUT';
    body = {nom, prenom, email, role};
    if(pwd) { if(pwd.length<6){msgEl.innerHTML='<span style="color:var(--rose)">Mot de passe trop court.</span>';return;} body.new_password=pwd; }
  } else {
    if(!pwd) { msgEl.innerHTML = '<span style="color:var(--rose)">Mot de passe requis.</span>'; return; }
    url = `${API}/users`; method = 'POST';
    body = {username:uname, password:pwd, nom, prenom, email, role};
  }

  try {
    const r = await fetch(url, {method, headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const d = await r.json();
    if(d.success) {
      toast(id ? '✓ Utilisateur mis à jour' : '✓ Utilisateur créé');
      closeModal('userModal');
      loadUsers();
      loadStats();
    } else {
      msgEl.innerHTML = `<span style="color:var(--rose)">${d.error}</span>`;
    }
  } catch {
    msgEl.innerHTML = '<span style="color:var(--rose)">Erreur serveur.</span>';
  }
}

async function deleteUser(id, username) {
  if(!confirm(`Supprimer @${username} ? Toutes les données seront effacées.`)) return;
  try {
    const r = await fetch(`${API}/users/${id}`, {method:'DELETE'});
    const d = await r.json();
    if(d.success) { toast('🗑 Utilisateur supprimé'); loadUsers(); loadStats(); }
    else toast(d.error||'Erreur', 'err');
  } catch { toast('Erreur serveur', 'err'); }
}

async function openUserDetail(id) {
  document.getElementById('detailTitle').textContent = 'Détail utilisateur #' + id;
  document.getElementById('detailBody').innerHTML = '<div class="empty">Chargement…</div>';
  openModal('detailModal');
  try {
    const r = await fetch(`${API}/users/${id}`);
    const d = await r.json();
    if(!d.success) throw new Error(d.error);
    const u = d.user;
    const di = (k,v) => `<div class="di"><div class="dk">${k}</div><div class="dv">${v||'—'}</div></div>`;
    document.getElementById('detailBody').innerHTML = `
      <div class="detail-grid" style="margin-bottom:1rem">
        ${di('Username','@'+u.username)}
        ${di('Rôle',`<span class="badge ${u.role}">${u.role}</span>`)}
        ${di('Nom complet',[u.prenom,u.nom].filter(Boolean).join(' '))}
        ${di('Email',u.email)}
        ${di('Téléphone',u.phone)}
        ${di('Wilaya',u.wilaya)}
        ${di('Établissement',u.etablissement)}
        ${di('Spécialité',u.specialite)}
        ${di('Créé le',(u.created_at||'').slice(0,10))}
        ${di('Prédictions',d.pred_count)}
      </div>
      ${d.recent_predictions.length ? `<div style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:.5rem">Dernières prédictions</div>
      <div style="display:flex;flex-direction:column;gap:.35rem">
        ${d.recent_predictions.map(p=>`<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:.5rem .75rem;display:flex;align-items:center;gap:.75rem;font-size:.78rem">
          <span class="badge ${p.risk_level}">${p.risk_level}</span>
          <span style="font-family:'JetBrains Mono',monospace;font-weight:700">${p.percentage!=null?p.percentage.toFixed(1)+'%':'—'}</span>
          <span style="color:var(--muted);margin-left:auto">${(p.predicted_at||'').slice(0,10)}</span>
        </div>`).join('')}
      </div>` : ''}`;
  } catch(e) {
    document.getElementById('detailBody').innerHTML = `<div class="empty">Erreur : ${e.message}</div>`;
  }
}

// ── Admins ─────────────────────────────────────────────
async function loadAdmins() {
  const wrap = document.getElementById('adminsTableWrap');
  wrap.innerHTML = '<div class="empty">Chargement…</div>';
  try {
    const r = await fetch(`${API}/admins`);
    const d = await r.json();
    if(!d.success||!d.admins.length) { wrap.innerHTML='<div class="empty">Aucun admin.</div>'; return; }
    wrap.innerHTML = `<table>
      <thead><tr><th>ID</th><th>Nom d'utilisateur</th><th>Créé le</th><th>Actions</th></tr></thead>
      <tbody>${d.admins.map(a=>`<tr>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--muted)">#${a.id}</span></td>
        <td><strong>⚡ ${a.username}</strong></td>
        <td style="font-size:.75rem;color:var(--muted)">${(a.created_at||'').slice(0,10)}</td>
        <td><button class="btn btn-danger btn-sm" onclick="deleteAdmin(${a.id},'${a.username}')">🗑 Supprimer</button></td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch { wrap.innerHTML = '<div class="empty">Erreur.</div>'; }
}

async function saveAdmin() {
  const uname = document.getElementById('amUsername').value.trim();
  const pwd   = document.getElementById('amPwd').value;
  const msgEl = document.getElementById('amMsg');
  msgEl.innerHTML = '';
  if(!uname||!pwd) { msgEl.innerHTML='<span style="color:var(--rose)">Champs requis.</span>'; return; }
  try {
    const r = await fetch(`${API}/admins`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:uname, password:pwd})});
    const d = await r.json();
    if(d.success) { toast('✓ Admin créé'); closeModal('adminModal'); loadAdmins(); }
    else msgEl.innerHTML = `<span style="color:var(--rose)">${d.error}</span>`;
  } catch { msgEl.innerHTML = '<span style="color:var(--rose)">Erreur serveur.</span>'; }
}

async function deleteAdmin(id, uname) {
  if(!confirm(`Supprimer l'admin @${uname} ?`)) return;
  try {
    const r = await fetch(`${API}/admins/${id}`, {method:'DELETE'});
    const d = await r.json();
    if(d.success) { toast('🗑 Admin supprimé'); loadAdmins(); }
    else toast(d.error||'Erreur', 'err');
  } catch { toast('Erreur serveur', 'err'); }
}

// ── Auto login check on load ───────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const r = await fetch(`${API}/me`);
    const d = await r.json();
    if(d.success) {
      currentAdmin = d.admin;
      document.getElementById('adminChip').textContent = '⚡ ' + d.admin;
      enterApp();
    }
  } catch {}
});
</script>
</body>
</html>
"""