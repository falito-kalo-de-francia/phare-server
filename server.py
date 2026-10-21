import http.server
import socketserver
import json
import time
import uuid
import os
import hashlib
import base64
import sys
import getpass
import secrets
import traceback
import threading
from urllib.parse import urlparse, parse_qs
import signal
import urllib.request
import urllib.error

PORT = int(os.environ.get("PORT", os.environ.get("PHARE_PORT", "8080")))
DATABASE_URL = os.environ.get("DATABASE_URL", os.environ.get("PHARE_DB_FILE", "phare_server_db.json"))
if DATABASE_URL.startswith("sqlite:///"):
    DATABASE_URL = DATABASE_URL.replace("sqlite:///", "")

IS_POSTGRES = DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")

if IS_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET_NAME", "phare-media")

AUDIT_LOG_FILE = os.environ.get("PHARE_AUDIT_LOG", os.environ.get("AUDIT_LOG_FILE", "audit.log"))
MEDIA_DIR = os.environ.get("PHARE_MEDIA_DIR", os.environ.get("MEDIA_DIR", "media_uploads"))
os.makedirs(MEDIA_DIR, exist_ok=True)

db_lock = threading.Lock()
server_start_time = time.time()

def log_structured(level, component, action, message, **kwargs):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    entry = {
        "timestamp": timestamp,
        "level": level,
        "component": component,
        "action": action,
        "message": message,
        **kwargs
    }
    print(json.dumps(entry))

def log_audit(action, email, ip, details=""):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    log_line = f"[{timestamp}] [AUDIT] IP: {ip} | User: {email} | Action: {action} | Details: {details}\n"
    print(log_line.strip())
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"[SERVER] Error writing to audit.log: {e}")

    if IS_POSTGRES:
        try:
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO audit_logs (action, email, ip, details) VALUES (%s, %s, %s, %s)",
                (action, email or "system", ip or "internal", details)
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"[SERVER] CRITICAL ERROR writing audit log to PostgreSQL: {e}")
            raise e

def init_postgres_db():
    if not IS_POSTGRES:
        return
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email VARCHAR(255) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL,
                iterations INT NOT NULL DEFAULT 100000,
                role VARCHAR(50) NOT NULL,
                site VARCHAR(50) NOT NULL,
                agent_id VARCHAR(255)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash VARCHAR(255) PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                site VARCHAR(50) NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                supervisor_pin_validated_at DOUBLE PRECISION DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS agents (
                id VARCHAR(255) PRIMARY KEY,
                full_name VARCHAR(255),
                role VARCHAR(50),
                status VARCHAR(50),
                battery_level INT,
                latitude DOUBLE PRECISION,
                longitude DOUBLE PRECISION,
                precision DOUBLE PRECISION,
                last_connection BIGINT,
                site_category VARCHAR(50)
            );
            CREATE TABLE IF NOT EXISTS events (
                id VARCHAR(255) PRIMARY KEY,
                agent_id VARCHAR(255),
                type VARCHAR(100),
                timestamp BIGINT,
                payload TEXT,
                site_category VARCHAR(50)
            );
            CREATE TABLE IF NOT EXISTS main_courante (
                entry_id VARCHAR(255) PRIMARY KEY,
                site_category VARCHAR(50),
                agent_name VARCHAR(255),
                event_type VARCHAR(100),
                content TEXT,
                attachments TEXT,
                created_by VARCHAR(255),
                server_received_at BIGINT,
                status VARCHAR(50),
                agent_signed BOOLEAN,
                agent_signed_by VARCHAR(255),
                agent_signed_at BIGINT,
                chef_de_poste_signed BOOLEAN,
                chef_de_poste_signed_by VARCHAR(255),
                chef_de_poste_signed_at BIGINT,
                hdc_signed BOOLEAN,
                hdc_signed_by VARCHAR(255),
                hdc_signed_at BIGINT,
                gph_signed BOOLEAN,
                gph_signed_by VARCHAR(255),
                gph_signed_at BIGINT
            );
            CREATE TABLE IF NOT EXISTS rounds (
                round_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255),
                description TEXT,
                active BOOLEAN,
                configuration_version INT,
                points TEXT,
                created_at BIGINT,
                updated_at BIGINT
            );
            CREATE TABLE IF NOT EXISTS media_categories (
                filename VARCHAR(255) PRIMARY KEY,
                site_category VARCHAR(50)
            );
            CREATE TABLE IF NOT EXISTS kv_store (
                key VARCHAR(255) PRIMARY KEY,
                value TEXT
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("[SERVER] PostgreSQL tables initialized successfully.")
    except Exception as e:
        print(f"[SERVER] Error initializing PostgreSQL tables: {e}")

def load_db():
    data = {
        "agents": {},
        "events": [],
        "main_courante": [],
        "rounds": {},
        "media_categories": {},
        "users": {},
        "sessions": {}
    }
    if IS_POSTGRES:
        init_postgres_db()
        try:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor(cursor_factory=RealDictCursor)

            # users
            cur.execute("SELECT * FROM users")
            for row in cur.fetchall():
                email = row["email"]
                p_hash = row.get("password_hash") or row.get("hash")
                data["users"][email] = {
                    "email": email,
                    "password_hash": p_hash,
                    "salt": row["salt"],
                    "iterations": row["iterations"],
                    "role": row["role"],
                    "site": row["site"],
                    "agentId": row.get("agent_id")
                }

            # sessions
            cur.execute("SELECT * FROM sessions")
            for row in cur.fetchall():
                data["sessions"][row["token_hash"]] = {
                    "email": row["email"],
                    "role": row["role"],
                    "site": row["site"],
                    "expires_at": row["expires_at"],
                    "supervisor_pin_validated_at": row["supervisor_pin_validated_at"]
                }

            # agents
            cur.execute("SELECT * FROM agents")
            for row in cur.fetchall():
                data["agents"][row["id"]] = {
                    "id": row["id"],
                    "fullName": row["full_name"],
                    "role": row["role"],
                    "status": row["status"],
                    "batteryLevel": row["battery_level"],
                    "latitude": row["latitude"],
                    "longitude": row["longitude"],
                    "precision": row["precision"],
                    "lastConnection": row["last_connection"],
                    "siteCategory": row["site_category"]
                }

            # events
            cur.execute("SELECT * FROM events")
            for row in cur.fetchall():
                ev = json.loads(row["payload"]) if row["payload"] else {}
                ev["id"] = row["id"]
                ev["agentId"] = row["agent_id"]
                ev["type"] = row["type"]
                ev["timestamp"] = row["timestamp"]
                ev["siteCategory"] = row["site_category"]
                data["events"].append(ev)

            # main_courante
            cur.execute("SELECT * FROM main_courante")
            for row in cur.fetchall():
                entry = {
                    "entryId": row["entry_id"],
                    "siteCategory": row["site_category"],
                    "agentName": row["agent_name"],
                    "eventType": row["event_type"],
                    "content": row["content"],
                    "attachments": json.loads(row["attachments"]) if row["attachments"] else [],
                    "createdBy": row["created_by"],
                    "serverReceivedAt": row["server_received_at"],
                    "status": row["status"]
                }
                for flag in ["agent_signed", "chef_de_poste_signed", "hdc_signed", "gph_signed"]:
                    camel_flag = "".join(w.capitalize() if i > 0 else w for i, w in enumerate(flag.split('_')))
                    if row.get(flag):
                        entry[camel_flag] = True
                        if row.get(f"{flag}_by"):
                            entry[f"{camel_flag}By"] = row[f"{flag}_by"]
                        if row.get(f"{flag}_at"):
                            entry[f"{camel_flag}At"] = row[f"{flag}_at"]
                data["main_courante"].append(entry)

            # rounds
            cur.execute("SELECT * FROM rounds")
            for row in cur.fetchall():
                data["rounds"][row["round_id"]] = {
                    "roundId": row["round_id"],
                    "name": row["name"],
                    "description": row["description"],
                    "active": row["active"],
                    "configurationVersion": row["configuration_version"],
                    "points": json.loads(row["points"]) if row["points"] else [],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"]
                }

            # media_categories
            cur.execute("SELECT * FROM media_categories")
            for row in cur.fetchall():
                data["media_categories"][row["filename"]] = row["site_category"]

            # kv_store for supervisor_auth
            cur.execute("SELECT value FROM kv_store WHERE key = 'supervisor_auth'")
            res = cur.fetchone()
            if res and res["value"]:
                data["supervisor_auth"] = json.loads(res["value"])

            cur.close()
            conn.close()
        except Exception as e:
            print(f"[SERVER] Error loading from PostgreSQL: {e}")
    else:
        db_path = DATABASE_URL
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        data.update(loaded)
            except Exception as e:
                print(f"[SERVER] Error loading DB: {e}")

    # Purge de l'ancienne ronde de démonstration (points fictifs à Paris) si elle est encore en base
    DEMO_NFC = {"NFC_A101", "NFC_B102", "NFC_C103", "NFC_D104"}
    for rid in list(data.get("rounds", {}).keys()):
        pts = data["rounds"][rid].get("points", [])
        if data["rounds"][rid].get("name") == "Ronde Générale - Site Principal" and pts and all(p.get("nfcId") in DEMO_NFC for p in pts):
            del data["rounds"][rid]
    if "supervisor_auth" not in data:
        data["supervisor_auth"] = None

    return data

# Handle command-line setup for supervisor PIN
if "--setup-supervisor-pin" in sys.argv:
    print("==================================================")
    print("PHARE 2.0 - CONFIGURATION DU PIN SUPERVISEUR")
    print("==================================================")
    try:
        pin = getpass.getpass("Entrez le nouveau PIN superviseur (6 chiffres minimum) : ")
        if len(pin) < 6 or not pin.isdigit():
            print("Erreur : Le PIN doit comporter au moins 6 chiffres numériques.")
            sys.exit(1)
        confirm = getpass.getpass("Confirmez le nouveau PIN superviseur : ")
        if pin != confirm:
            print("Erreur : Les PINs ne correspondent pas.")
            sys.exit(1)

        salt = os.urandom(16)
        iterations = 100000
        pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt, iterations).hex()

        db_data = load_db()
        db_data["supervisor_auth"] = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "hash": pin_hash,
            "iterations": iterations
        }
        # Save back
        global db
        db = db_data
        save_db()
        print("Succès : PIN superviseur configuré et stocké de manière sécurisée (PBKDF2-HMAC-SHA256).")
    except Exception as e:
        print(f"Erreur lors de la configuration du PIN : {e}")
    sys.exit(0)

# Handle command-line support for --add-user
if "--add-user" in sys.argv:
    print("==================================================")
    print("PHARE 2.0 - AJOUT D'UN UTILISATEUR")
    print("==================================================")
    try:
        email = input("Email : ").strip()
        if not email or "@" not in email:
            print("Erreur : Email invalide.")
            sys.exit(1)
        role = input("Rôle (AGENT | SUPERVISEUR) [AGENT] : ").strip().upper()
        if not role:
            role = "AGENT"
        if role not in ["AGENT", "SUPERVISEUR"]:
            print("Erreur : Rôle invalide (AGENT ou SUPERVISEUR).")
            sys.exit(1)

        password = getpass.getpass("Mot de passe : ")
        if role == "SUPERVISEUR":
            if len(password) < 10:
                print("Erreur : Le mot de passe pour un SUPERVISEUR doit contenir au moins 10 caractères.")
                sys.exit(1)
            site = "TOUS"
            print("Périmètre assigné automatiquement au SUPERVISEUR : TOUS")
        else:
            if len(password) < 4:
                print("Erreur : Mot de passe trop court (4 caractères min).")
                sys.exit(1)
            site = input("Site / Périmètre (PATROUILLE | AERO_HOTELS | HOTELS) [PATROUILLE] : ").strip().upper()
            if not site:
                site = "PATROUILLE"
            if site == "AERO":
                site = "AERO_HOTELS"
            if site not in ["PATROUILLE", "AERO_HOTELS", "HOTELS"]:
                print("Erreur : Site invalide (PATROUILLE, AERO_HOTELS, HOTELS).")
                sys.exit(1)

        salt = os.urandom(16)
        iterations = 100000
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations).hex()

        db_data = load_db()
        if "users" not in db_data:
            db_data["users"] = {}

        agent_id = f"agent_{email.split('@')[0].lower()}" if role == "AGENT" else None

        db_data["users"][email] = {
            "email": email,
            "password_hash": password_hash,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "iterations": iterations,
            "role": role,
            "site": site,
            "agentId": agent_id
        }
        global users
        users = db_data["users"]
        save_db()
        print(f"Succès : Utilisateur {email} ({role}, {site}) ajouté.")
    except Exception as e:
        print(f"Erreur lors de l'ajout de l'utilisateur : {e}")
    sys.exit(0)

db = load_db()
agents = db.get("agents", {})
events = db.get("events", [])
main_courante_events = db.get("main_courante", [])
rounds = db.get("rounds", {})
media_categories = db.get("media_categories", {})
users = db.get("users", {})
sessions = db.get("sessions", {})
login_failures = {}
supervisor_login_failures = {}
acknowledgements = set()
clients = []

# If no users exist, display message
if not users:
    print("Créez un compte avec python server.py --add-user")

def bootstrap_admin_from_env():
    with db_lock:
        if not users:
            admin_email = os.environ.get("PHARE_ADMIN_EMAIL")
            admin_pwd = os.environ.get("PHARE_ADMIN_PASSWORD")
            if admin_email and admin_pwd:
                if len(admin_pwd) < 10:
                    print("[SERVER] WARNING: Admin password from env must be at least 10 chars.")
                    return
                salt = os.urandom(16)
                iterations = 100000
                pwd_hash = hashlib.pbkdf2_hmac('sha256', admin_pwd.encode('utf-8'), salt, iterations).hex()
                agent_id = f"agent_{admin_email.split('@')[0]}"
                users[admin_email] = {
                    "email": admin_email,
                    "password_hash": pwd_hash,
                    "salt": base64.b64encode(salt).decode('utf-8'),
                    "iterations": iterations,
                    "role": "SUPERVISEUR",
                    "site": "TOUS",
                    "agentId": agent_id
                }
                save_db()
                print(f"[SERVER] Successfully bootstrapped initial admin account: {admin_email}")

bootstrap_admin_from_env()

def save_db():
    if IS_POSTGRES:
        try:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()

            # users
            for email, u in users.items():
                p_hash = u.get("password_hash") or u.get("hash", "")
                cur.execute("""
                    INSERT INTO users (email, password_hash, salt, iterations, role, site, agent_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (email) DO UPDATE SET
                        password_hash = EXCLUDED.password_hash,
                        salt = EXCLUDED.salt,
                        iterations = EXCLUDED.iterations,
                        role = EXCLUDED.role,
                        site = EXCLUDED.site,
                        agent_id = EXCLUDED.agent_id
                """, (email, p_hash, u["salt"], u.get("iterations", 100000), u["role"], u["site"], u.get("agentId")))

            # sessions
            cur.execute("DELETE FROM sessions")
            for token_hash, s in sessions.items():
                cur.execute("""
                    INSERT INTO sessions (token_hash, email, role, site, expires_at, supervisor_pin_validated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (token_hash, s["email"], s["role"], s["site"], s["expires_at"], s.get("supervisor_pin_validated_at", 0)))

            # agents
            for aid, ag in agents.items():
                cur.execute("""
                    INSERT INTO agents (id, full_name, role, status, battery_level, latitude, longitude, precision, last_connection, site_category)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        full_name = EXCLUDED.full_name,
                        role = EXCLUDED.role,
                        status = EXCLUDED.status,
                        battery_level = EXCLUDED.battery_level,
                        latitude = EXCLUDED.latitude,
                        longitude = EXCLUDED.longitude,
                        precision = EXCLUDED.precision,
                        last_connection = EXCLUDED.last_connection,
                        site_category = EXCLUDED.site_category
                """, (aid, ag.get("fullName"), ag.get("role"), ag.get("status"), ag.get("batteryLevel"),
                      ag.get("latitude"), ag.get("longitude"), ag.get("precision"), ag.get("lastConnection"), ag.get("siteCategory")))

            # events
            for ev in events:
                eid = ev.get("id")
                if not eid:
                    continue
                payload_copy = dict(ev)
                payload_copy.pop("id", None)
                payload_copy.pop("agentId", None)
                payload_copy.pop("type", None)
                payload_copy.pop("timestamp", None)
                payload_copy.pop("siteCategory", None)
                cur.execute("""
                    INSERT INTO events (id, agent_id, type, timestamp, payload, site_category)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        agent_id = EXCLUDED.agent_id,
                        type = EXCLUDED.type,
                        timestamp = EXCLUDED.timestamp,
                        payload = EXCLUDED.payload,
                        site_category = EXCLUDED.site_category
                """, (eid, ev.get("agentId"), ev.get("type"), ev.get("timestamp"), json.dumps(payload_copy), ev.get("siteCategory")))

            # main_courante
            for mc in main_courante_events:
                eid = mc.get("entryId")
                if not eid:
                    continue
                cur.execute("""
                    INSERT INTO main_courante (
                        entry_id, site_category, agent_name, event_type, content, attachments,
                        created_by, server_received_at, status,
                        agent_signed, agent_signed_by, agent_signed_at,
                        chef_de_poste_signed, chef_de_poste_signed_by, chef_de_poste_signed_at,
                        hdc_signed, hdc_signed_by, hdc_signed_at,
                        gph_signed, gph_signed_by, gph_signed_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (entry_id) DO UPDATE SET
                        site_category = EXCLUDED.site_category,
                        agent_name = EXCLUDED.agent_name,
                        event_type = EXCLUDED.event_type,
                        content = EXCLUDED.content,
                        attachments = EXCLUDED.attachments,
                        created_by = EXCLUDED.created_by,
                        server_received_at = EXCLUDED.server_received_at,
                        status = EXCLUDED.status,
                        agent_signed = EXCLUDED.agent_signed,
                        agent_signed_by = EXCLUDED.agent_signed_by,
                        agent_signed_at = EXCLUDED.agent_signed_at,
                        chef_de_poste_signed = EXCLUDED.chef_de_poste_signed,
                        chef_de_poste_signed_by = EXCLUDED.chef_de_poste_signed_by,
                        chef_de_poste_signed_at = EXCLUDED.chef_de_poste_signed_at,
                        hdc_signed = EXCLUDED.hdc_signed,
                        hdc_signed_by = EXCLUDED.hdc_signed_by,
                        hdc_signed_at = EXCLUDED.hdc_signed_at,
                        gph_signed = EXCLUDED.gph_signed,
                        gph_signed_by = EXCLUDED.gph_signed_by,
                        gph_signed_at = EXCLUDED.gph_signed_at
                """, (
                    eid, mc.get("siteCategory"), mc.get("agentName"), mc.get("eventType"),
                    mc.get("content"), json.dumps(mc.get("attachments", [])),
                    mc.get("createdBy"), mc.get("serverReceivedAt"), mc.get("status"),
                    mc.get("agentSigned", False), mc.get("agentSignedBy"), mc.get("agentSignedAt"),
                    mc.get("chefDePosteSigned", False), mc.get("chefDePosteSignedBy"), mc.get("chefDePosteSignedAt"),
                    mc.get("hdcSigned", False), mc.get("hdcSignedBy"), mc.get("hdcSignedAt"),
                    mc.get("gphSigned", False), mc.get("gphSignedBy"), mc.get("gphSignedAt")
                ))

            # rounds
            for rid, r in rounds.items():
                cur.execute("""
                    INSERT INTO rounds (round_id, name, description, active, configuration_version, points, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (round_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        active = EXCLUDED.active,
                        configuration_version = EXCLUDED.configuration_version,
                        points = EXCLUDED.points,
                        updated_at = EXCLUDED.updated_at
                """, (rid, r.get("name"), r.get("description"), r.get("active"), r.get("configurationVersion"),
                      json.dumps(r.get("points", [])), r.get("createdAt"), r.get("updatedAt")))

            # media_categories
            for fn, sc in media_categories.items():
                cur.execute("""
                    INSERT INTO media_categories (filename, site_category)
                    VALUES (%s, %s)
                    ON CONFLICT (filename) DO UPDATE SET site_category = EXCLUDED.site_category
                """, (fn, sc))

            # supervisor_auth in kv_store
            sup_auth = db.get("supervisor_auth")
            if sup_auth:
                cur.execute("""
                    INSERT INTO kv_store (key, value)
                    VALUES ('supervisor_auth', %s)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                """, (json.dumps(sup_auth),))

            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"[SERVER] CRITICAL Error saving to PostgreSQL: {e}")
            if 'conn' in locals() and conn:
                try: conn.close()
                except: pass
            raise e
    else:
        try:
            data = {
                "agents": agents,
                "events": events,
                "main_courante": main_courante_events,
                "rounds": rounds,
                "media_categories": media_categories,
                "supervisor_auth": db.get("supervisor_auth"),
                "users": users,
                "sessions": sessions
            }
            db_path = DATABASE_URL
            temp_file = db_path + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(temp_file, db_path)
        except Exception as e:
            print(f"[SERVER] Error saving DB atomically: {e}")

def upload_media_to_supabase(filename, data_bytes, content_type):
    if not SUPABASE_URL or not SUPABASE_KEY:
        return False
    try:
        url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{SUPABASE_BUCKET}/{filename}"
        req = urllib.request.Request(url, method="POST", data=data_bytes)
        req.add_header("Authorization", f"Bearer {SUPABASE_KEY}")
        req.add_header("Content-Type", content_type)
        req.add_header("x-upsert", "true")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        print(f"[SERVER] Supabase Storage upload error: {e}")
        return False

def get_media_from_supabase(filename):
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    try:
        url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{SUPABASE_BUCKET}/{filename}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {SUPABASE_KEY}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                return resp.read()
    except Exception as e:
        print(f"[SERVER] Supabase Storage download error: {e}")
    return None

def compute_agent_status(last_conn_ms):
    now_ms = int(1000 * time.time())
    diff_sec = (now_ms - last_conn_ms) / 1000.0
    if diff_sec < 90:
        return "EN_LIGNE"
    elif diff_sec < 600:
        return "PERDU"
    else:
        return "HORS_LIGNE"

def broadcast(message_dict, target_site=None):
    msg_str = json.dumps(message_dict)
    dead_clients = []
    for client, client_info in clients:
        try:
            c_role = client_info.get("role", "AGENT")
            c_site = client_info.get("site", "PATROUILLE").upper()
            if c_site == "AERO": c_site = "AERO_HOTELS"

            if c_role == "SUPERVISEUR" and c_site == "TOUS":
                pass
            elif target_site:
                t_site = target_site.upper()
                if t_site == "AERO": t_site = "AERO_HOTELS"
                if t_site != c_site:
                    continue
            else:
                msg_site = message_dict.get("siteCategory") or message_dict.get("site")
                if msg_site:
                    ms = msg_site.upper()
                    if ms == "AERO": ms = "AERO_HOTELS"
                    if ms != c_site:
                        continue

            payload = msg_str.encode('utf-8')
            length = len(payload)
            frame = bytearray()
            frame.append(0x81)
            if length <= 125:
                frame.append(length)
            elif length <= 65535:
                frame.append(126)
                frame.extend(length.to_bytes(2, 'big'))
            else:
                frame.append(127)
                frame.extend(length.to_bytes(8, 'big'))
            frame.extend(payload)
            client.sendall(frame)
        except Exception:
            dead_clients.append(client)
    for dc in dead_clients:
        for i, (c, _) in enumerate(clients):
            if c == dc:
                clients.pop(i)
                break

def check_access(session, resource, method, target_site=None, client_ip=""):
    if not session:
        return False, 401, "Unauthorized"
    role = session.get("role", "AGENT")
    user_site = session.get("site", "PATROUILLE").upper()
    if user_site == "AERO": user_site = "AERO_HOTELS"
    email = session.get("email", "unknown")

    if role == "SUPERVISEUR":
        if user_site == "TOUS":
            return True, 200, "OK"
        if target_site:
            t_site = target_site.upper()
            if t_site == "AERO": t_site = "AERO_HOTELS"
            if t_site != "TOUS" and t_site != user_site:
                log_audit("CROSS_SITE_ACCESS", email, client_ip, f"Supervisor {user_site} accessed {t_site} on {resource}")
        return True, 200, "OK"

    if role == "AGENT":
        if resource in ["/api/agents", "/api/events"] and method == "GET":
            log_audit("UNAUTHORIZED_AGENT_ACCESS", email, client_ip, f"Agent attempted GET {resource}")
            return False, 403, "Forbidden: Agent access denied to this endpoint"
        if resource == "/api/agents/acknowledge" or (resource == "/api/rounds" and method == "POST"):
            log_audit("UNAUTHORIZED_AGENT_ACCESS", email, client_ip, f"Agent attempted {method} {resource}")
            return False, 403, "Forbidden: Agent access denied to this endpoint"

        if target_site:
            t_site = target_site.upper()
            if t_site == "AERO": t_site = "AERO_HOTELS"
            if t_site != user_site:
                log_audit("CROSS_SITE_ACCESS", email, client_ip, f"Agent {user_site} accessed {t_site} on {resource}")
                return False, 403, "Forbidden: Cross-perimeter access denied"

    return True, 200, "OK"

class PhareServerHandler(http.server.BaseHTTPRequestHandler):
    current_session = None

    def authenticate_request(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ['/health', '/api/health', '/api/login', '/api/bootstrap'] or path == '/ws':
            return True

        if not users:
            self.send_response(503)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ERROR", "message": "Créez un compte avec python server.py --add-user"}).encode('utf-8'))
            return False

        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            self.send_response(401)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ERROR", "message": "Unauthorized: Missing or invalid Bearer token"}).encode('utf-8'))
            return False

        token = auth_header[7:].strip()
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

        with db_lock:
            session = sessions.get(token_hash)
            now = time.time()
            if not session or session["expires_at"] < now:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": "Unauthorized: Invalid or expired token"}).encode('utf-8'))
                return False
            self.current_session = session
        return True

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            client_ip = self.client_address[0]

            if path == '/api/bootstrap':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    data = {}

                with db_lock:
                    if users:
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Bootstrap already completed"}).encode('utf-8'))
                        return

                    setup_token = os.environ.get("PHARE_SETUP_TOKEN")
                    if not setup_token:
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Bootstrap token not configured on server"}).encode('utf-8'))
                        return

                    auth_token = self.headers.get('X-Setup-Token', '')
                    if not secrets.compare_digest(auth_token, setup_token):
                        log_audit("BOOTSTRAP_FAILED", "unknown", client_ip, "Invalid setup token")
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Invalid setup token"}).encode('utf-8'))
                        return

                    email = data.get('email')
                    pwd = data.get('password')
                    if not email or not pwd or len(pwd) < 10:
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Email and password (min 10 chars) required"}).encode('utf-8'))
                        return

                    salt = os.urandom(16)
                    iterations = 100000
                    pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, iterations).hex()
                    agent_id = f"agent_{email.split('@')[0]}"
                    users[email] = {
                        "email": email,
                        "password_hash": pwd_hash,
                        "salt": base64.b64encode(salt).decode('utf-8'),
                        "iterations": iterations,
                        "role": "SUPERVISEUR",
                        "site": "TOUS",
                        "agentId": agent_id
                    }
                    save_db()
                    log_audit("BOOTSTRAP_SUCCESS", email, client_ip, "Initial supervisor created")
                    self.send_json({"status": "OK", "message": "Initial supervisor created successfully"})
                return

            if not users:
                self.send_response(503)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": "Créez un compte avec python server.py --add-user"}).encode('utf-8'))
                return

            if not self.authenticate_request():
                return

            if path == '/ws':
                self.handle_websocket()
                return

            if path == '/api/login':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "Malformed JSON"}).encode('utf-8'))
                    return

                email = data.get('email', '').strip()
                password = data.get('password', '')

                with db_lock:
                    now = time.time()
                    fail_key = (email, client_ip)
                    fail_info = login_failures.get(fail_key, {"count": 0, "blocked_until": 0.0})
                    if now < fail_info["blocked_until"]:
                        remaining = int(fail_info["blocked_until"] - now)
                        log_audit("LOGIN_BLOCKED", email, client_ip, f"Blocked for {remaining}s")
                        self.send_response(429)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": f"Trop de tentatives échouées. Compte bloqué pendant {remaining}s."}).encode('utf-8'))
                        return

                    user = users.get(email)
                    if not user:
                        fail_info["count"] += 1
                        if fail_info["count"] >= 5:
                            fail_info["blocked_until"] = now + 60
                            fail_info["count"] = 0
                        login_failures[fail_key] = fail_info
                        log_audit("LOGIN_FAILED", email, client_ip, "User not found")
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Identifiants invalides"}).encode('utf-8'))
                        return

                    salt = base64.b64decode(user["salt"])
                    iterations = user.get("iterations", 100000)
                    p_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations).hex()

                    stored_pwd_hash = user.get("password_hash") or user.get("hash")
                    if p_hash == stored_pwd_hash:
                        login_failures.pop(fail_key, None)
                        token = secrets.token_hex(32)
                        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                        expires_at = now + 12 * 3600
                        session_data = {
                            "email": email,
                            "role": user["role"],
                            "site": user["site"],
                            "expires_at": expires_at,
                            "supervisor_pin_validated_at": 0
                        }
                        sessions[token_hash] = session_data
                        save_db()
                        log_audit("LOGIN_SUCCESS", email, client_ip, f"Role: {user['role']}, Site: {user['site']}")
                        self.send_json({"status": "OK", "token": token, "role": user["role"], "site": user["site"]})
                    else:
                        fail_info["count"] += 1
                        if fail_info["count"] >= 5:
                            fail_info["blocked_until"] = now + 60
                            fail_info["count"] = 0
                        login_failures[fail_key] = fail_info
                        log_audit("LOGIN_FAILED", email, client_ip, "Invalid password")
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Identifiants invalides"}).encode('utf-8'))
                return

            allowed, code, msg = check_access(self.current_session, path, "POST", client_ip=client_ip)
            if not allowed:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": msg}).encode('utf-8'))
                return

            if path == '/api/main-courante/upload':
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 15 * 1024 * 1024:
                    self.send_response(413)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "Payload Too Large (max 15MB)"}).encode('utf-8'))
                    return

                body_bytes = self.rfile.read(content_length)
                raw_filename = self.headers.get('X-Filename', f"media_{int(time.time())}.dat")
                ext = os.path.splitext(raw_filename)[1] or ".dat"
                secure_filename = f"{uuid.uuid4()}{ext}"

                user_site = self.current_session['site'].upper()
                if user_site == 'AERO': user_site = 'AERO_HOTELS'
                if self.current_session['role'] == 'SUPERVISEUR':
                    hdr_site = (self.headers.get('X-Site-Category') or '').upper()
                    if hdr_site == 'AERO': hdr_site = 'AERO_HOTELS'
                    if hdr_site not in ('PATROUILLE', 'AERO_HOTELS', 'HOTELS'):
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "En-tête X-Site-Category requis pour un superviseur (PATROUILLE | AERO_HOTELS | HOTELS)"}).encode('utf-8'))
                        return
                    user_site = hdr_site

                content_type = "image/jpeg" if secure_filename.endswith((".jpg", ".jpeg", ".png")) else "video/mp4"
                supabase_success = upload_media_to_supabase(secure_filename, body_bytes, content_type)

                file_path = os.path.join(MEDIA_DIR, secure_filename)
                try:
                    with open(file_path, "wb") as f:
                        f.write(body_bytes)
                except Exception as ex:
                    print(f"[SERVER] Local media save warning: {ex}")

                with db_lock:
                    media_categories[secure_filename] = user_site
                    save_db()
                log_audit("MEDIA_UPLOAD", self.current_session['email'], client_ip, f"File: {secure_filename} ({len(body_bytes)} bytes, Supabase: {supabase_success})")
                self.send_json({"status": "OK", "filename": secure_filename, "url": f"/api/media/{secure_filename}"})
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body) if body else {}
            except Exception:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": "Malformed JSON"}).encode('utf-8'))
                return

            if path == '/api/supervisor/setup':
                if self.current_session['role'] != 'SUPERVISEUR':
                    self.send_response(403)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Requires SUPERVISEUR role"}).encode('utf-8'))
                    return

                with db_lock:
                    sup_auth = db.get("supervisor_auth")
                    if sup_auth and sup_auth.get("hash"):
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "PIN superviseur déjà configuré"}).encode('utf-8'))
                        return

                    pin = data.get('pin', '')
                    if len(pin) < 6 or not str(pin).isdigit():
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Le PIN doit comporter au moins 6 chiffres"}).encode('utf-8'))
                        return

                    salt = os.urandom(16)
                    iterations = 100000
                    pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt, iterations).hex()

                    db["supervisor_auth"] = {
                        "salt": base64.b64encode(salt).decode('utf-8'),
                        "hash": pin_hash,
                        "iterations": iterations
                    }
                    save_db()
                log_audit("SUPERVISEUR_SETUP", self.current_session['email'], client_ip, "PIN configured")
                self.send_json({"status": "OK", "message": "PIN superviseur configuré avec succès"})
                return

            if path == '/api/supervisor/auth':
                if self.current_session['role'] != 'SUPERVISEUR':
                    self.send_response(403)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Requires SUPERVISEUR role"}).encode('utf-8'))
                    return

                now = time.time()
                sup_fail = supervisor_login_failures.get(client_ip, {"count": 0, "blocked_until": 0.0})
                if now < sup_fail["blocked_until"]:
                    remaining = int(sup_fail["blocked_until"] - now)
                    self.send_response(429)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": f"Trop de tentatives PIN échouées. Bloqué pendant {remaining}s."}).encode('utf-8'))
                    return

                pin = data.get('pin', '')
                if len(pin) < 6:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "Le PIN superviseur doit comporter au moins 6 chiffres"}).encode('utf-8'))
                    return

                sup_auth = db.get("supervisor_auth", {})
                if not sup_auth or not sup_auth.get("hash"):
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "PIN non configuré"}).encode('utf-8'))
                    return
                salt_b64 = sup_auth.get("salt", "")
                stored_hash = sup_auth.get("hash", "")
                iterations = sup_auth.get("iterations", 100000)

                try:
                    salt_bytes = base64.b64decode(salt_b64)
                except Exception:
                    salt_bytes = b"phare_secure_salt_2025"

                pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt_bytes, iterations).hex()
                if pin_hash == stored_hash:
                    supervisor_login_failures.pop(client_ip, None)
                    with db_lock:
                        self.current_session["supervisor_pin_validated_at"] = time.time()
                        save_db()
                    token = str(uuid.uuid4())
                    log_audit("SUPERVISOR_PIN_SUCCESS", self.current_session['email'], client_ip)
                    self.send_json({"status": "OK", "token": token})
                else:
                    sup_fail["count"] += 1
                    if sup_fail["count"] >= 5:
                        sup_fail["blocked_until"] = now + 300
                        sup_fail["count"] = 0
                    supervisor_login_failures[client_ip] = sup_fail
                    log_audit("SUPERVISOR_PIN_FAILED", self.current_session['email'], client_ip, f"Attempt {sup_fail['count']}")
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "PIN superviseur incorrect"}).encode('utf-8'))
                return

            with db_lock:
                if path == '/api/agents/register':
                    email = self.current_session['email']
                    user_rec = users.get(email, {})
                    agent_id = user_rec.get("agentId") or f"agent_{email.split('@')[0].lower()}"

                    agents[agent_id] = {
                        "id": agent_id,
                        "fullName": data.get('name', email),
                        "role": data.get('role', self.current_session['role']),
                        "status": compute_agent_status(int(1000 * time.time())),
                        "batteryLevel": data.get('battery', 100),
                        "latitude": data.get('lat', 48.8566),
                        "longitude": data.get('lon', 2.3522),
                        "precision": data.get('accuracy', 5.0),
                        "lastConnection": int(1000 * time.time()),
                        "siteCategory": self.current_session['site']
                    }
                    save_db()
                    print(f"[SERVER] Agent registered: {agent_id} [{self.current_session['site']}]")
                    self.send_json({"status": "OK"})

                elif path == '/api/agents/heartbeat':
                    if self.current_session['role'] == 'SUPERVISEUR':
                        self.send_json({"status": "OK"})
                        return
                    email = self.current_session['email']
                    user_rec = users.get(email, {})
                    agent_id = user_rec.get("agentId") or f"agent_{email.split('@')[0].lower()}"
                    now_ms = int(1000 * time.time())
                    ag = agents.setdefault(agent_id, {"id": agent_id, "fullName": email, "role": "AGENT",
                                                      "siteCategory": self.current_session['site']})
                    ag["lastConnection"] = now_ms
                    ag["status"] = compute_agent_status(now_ms)
                    if data.get('battery') is not None:
                        ag["batteryLevel"] = data.get('battery')
                    save_db()
                    self.send_json({"status": "OK"})

                elif path.startswith('/api/agents/') and path.endswith('/position'):
                    email = self.current_session['email']
                    user_rec = users.get(email, {})
                    agent_id = user_rec.get("agentId") or f"agent_{email.split('@')[0].lower()}"

                    req_agent_id = data.get('agentId')
                    if req_agent_id and req_agent_id != agent_id and self.current_session['role'] != 'SUPERVISEUR':
                        log_audit("UNAUTHORIZED_AGENT_SPOOF", email, client_ip, f"Attempted posting position for {req_agent_id}")
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Cannot post position for another agent"}).encode('utf-8'))
                        return

                    if agent_id not in agents:
                        agents[agent_id] = {
                            "id": agent_id,
                            "fullName": email,
                            "role": "AGENT",
                            "batteryLevel": data.get('battery', 100),
                            "siteCategory": self.current_session['site']
                        }

                    agents[agent_id]["latitude"] = data.get('latitude')
                    agents[agent_id]["longitude"] = data.get('longitude')
                    agents[agent_id]["precision"] = data.get('precision')
                    agents[agent_id]["batteryLevel"] = data.get('battery')
                    agents[agent_id]["lastConnection"] = int(1000 * time.time())
                    agents[agent_id]["status"] = compute_agent_status(agents[agent_id]["lastConnection"])
                    save_db()

                    broadcast({
                        "type": "AGENT_POSITION_UPDATED",
                        "agentId": agent_id,
                        "latitude": data.get('latitude'),
                        "longitude": data.get('longitude'),
                        "precision": data.get('precision'),
                        "battery": data.get('battery'),
                        "timestamp": int(1000 * time.time()),
                        "siteCategory": self.current_session['site']
                    }, target_site=self.current_session['site'])
                    self.send_json({"status": "OK"})

                elif path == '/api/events':
                    email = self.current_session['email']
                    user_rec = users.get(email, {})
                    agent_id = user_rec.get("agentId") or f"agent_{email.split('@')[0].lower()}"

                    req_agent_id = data.get('agentId')
                    if req_agent_id and req_agent_id != agent_id and self.current_session['role'] != 'SUPERVISEUR':
                        log_audit("UNAUTHORIZED_AGENT_SPOOF", email, client_ip, f"Attempted posting event for {req_agent_id}")
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Cannot post event for another agent"}).encode('utf-8'))
                        return

                    data['agentId'] = agent_id
                    data['siteCategory'] = self.current_session['site']

                    event_id = data.get('id')
                    if not event_id:
                        self.send_response(400)
                        self.end_headers()
                        return
                    if any(e.get('id') == event_id for e in events):
                        self.send_json({"status": "DUPLICATE"})
                        return

                    events.append(data)
                    save_db()
                    event_type = data.get('type')
                    print(f"[SERVER] Event received from {agent_id}: {event_type} (id={event_id})")
                    if agent_id in agents:
                        if event_type == 'PTI_PRE_ALARM':
                            agents[agent_id]["status"] = "PRE_ALARME"
                        elif event_type == 'PTI_ALARM':
                            agents[agent_id]["status"] = "ALARME"
                        elif event_type in ['PTI_ACKNOWLEDGED', 'SERVICE_STARTED']:
                            agents[agent_id]["status"] = "EN_LIGNE"
                        elif event_type == 'SERVICE_STOPPED':
                            agents[agent_id]["status"] = "HORS_LIGNE"
                        save_db()

                    broadcast(data, target_site=self.current_session['site'])
                    self.send_json({"status": "RECEIVED"})

                elif path == '/api/main-courante/events':
                    entry_id = data.get('entryId')
                    user_site = self.current_session['site'].upper()
                    if user_site == 'AERO': user_site = 'AERO_HOTELS'

                    client_site = str(data.get('siteCategory') or user_site).upper()
                    if client_site == 'AERO': client_site = 'AERO_HOTELS'
                    if client_site != user_site and self.current_session['role'] != 'SUPERVISEUR':
                        log_audit("CROSS_SITE_WRITE", self.current_session['email'], client_ip, f"Attempted write to {client_site} from {user_site}")
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Strict server-side isolation — Cross-perimeter access denied"}).encode('utf-8'))
                        return

                    if self.current_session['role'] == 'SUPERVISEUR':
                        if client_site not in ('PATROUILLE', 'AERO_HOTELS', 'HOTELS'):
                            self.send_response(400)
                            self.send_header('Content-Type', 'application/json; charset=utf-8')
                            self.end_headers()
                            self.wfile.write(json.dumps({"status": "ERROR", "message": "siteCategory requis (PATROUILLE | AERO_HOTELS | HOTELS) pour un superviseur"}).encode('utf-8'))
                            return
                        entry_site = client_site
                    else:
                        entry_site = user_site
                    data['siteCategory'] = entry_site
                    data['createdBy'] = self.current_session['email']
                    data['serverReceivedAt'] = int(1000 * time.time())
                    if not entry_id:
                        self.send_response(400)
                        self.end_headers()
                        return
                    if any(e.get('entryId') == entry_id for e in main_courante_events):
                        self.send_json({"status": "DUPLICATE"})
                        return

                    main_courante_events.append(data)
                    save_db()
                    log_audit("MAIN_COURANTE_ADD", self.current_session['email'], client_ip, f"Entry {entry_id} [{entry_site}]")
                    broadcast({"type": "MAIN_COURANTE_ADDED", "entry": data}, target_site=entry_site)
                    self.send_json({"status": "RECEIVED"})

                elif path == '/api/agents/acknowledge':
                    agent_id = data.get('agentId')
                    event_id = data.get('eventId')
                    if not agent_id or not event_id:
                        self.send_response(400)
                        self.end_headers()
                        return
                    acknowledgements.add(event_id)
                    log_audit("ALARM_ACKNOWLEDGE", self.current_session['email'], client_ip, f"Agent: {agent_id}, Event: {event_id}")
                    if agent_id in agents:
                        agents[agent_id]["status"] = "EN_LIGNE"
                        save_db()
                    ack_event = {
                        "id": str(uuid.uuid4()),
                        "agentId": agent_id,
                        "type": "PTI_PC_ACKNOWLEDGED",
                        "timestamp": int(1000 * time.time()),
                        "payload": event_id,
                        "siteCategory": self.current_session['site']
                    }
                    events.append(ack_event)
                    save_db()
                    broadcast(ack_event)
                    self.send_json({"status": "ACKED"})

                elif path == '/api/rounds':
                    if self.current_session['role'] == 'SUPERVISEUR':
                        val_at = self.current_session.get("supervisor_pin_validated_at", 0)
                        if time.time() - val_at > 900:
                            self.send_response(403)
                            self.send_header('Content-Type', 'application/json; charset=utf-8')
                            self.end_headers()
                            self.wfile.write(json.dumps({"status": "ERROR", "message": "PIN superviseur requis (validité 15 min expirée)"}).encode('utf-8'))
                            return

                    round_id = data.get("roundId", f"round_{str(uuid.uuid4())[:8]}")
                    name = data.get("name")
                    if not name:
                        self.send_response(400)
                        self.end_headers()
                        return

                    points = data.get("points", [])
                    nfc_set = set()
                    for p in points:
                        nfc = p.get("nfcId")
                        if nfc in nfc_set:
                            self.send_json({"status": "ERROR", "message": f"Duplicate NFC UID: {nfc}"})
                            return
                        nfc_set.add(nfc)

                    rounds[round_id] = {
                        "roundId": round_id,
                        "name": name,
                        "description": data.get("description", ""),
                        "active": data.get("active", True),
                        "configurationVersion": rounds.get(round_id, {}).get("configurationVersion", 0) + 1,
                        "points": points,
                        "createdAt": rounds.get(round_id, {}).get("createdAt", int(1000 * time.time())),
                        "updatedAt": int(1000 * time.time())
                    }
                    save_db()
                    log_audit("ROUNDS_MODIFY", self.current_session['email'], client_ip, f"Round {name} ({round_id})")
                    self.send_json({"status": "OK", "roundId": round_id})

                else:
                    self.send_response(404)
                    self.end_headers()
        except Exception as e:
            traceback.print_exc()
            self.send_response(500)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ERROR", "message": str(e)}).encode('utf-8'))

    def do_PUT(self):
        try:
            if not users or not self.authenticate_request():
                return

            parsed = urlparse(self.path)
            path = parsed.path
            client_ip = self.client_address[0]

            allowed, code, msg = check_access(self.current_session, path, "PUT", client_ip=client_ip)
            if not allowed:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": msg}).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body) if body else {}
            except Exception:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": "Malformed JSON"}).encode('utf-8'))
                return

            if path.startswith('/api/main-courante/events/'):
                entryId = path.split('/')[-1]
                with db_lock:
                    target_entry = None
                    for e in main_courante_events:
                        if e.get('entryId') == entryId:
                            target_entry = e
                            break
                    if not target_entry:
                        self.send_response(404)
                        self.end_headers()
                        return

                    user_site = self.current_session['site'].upper()
                    if user_site == 'AERO': user_site = 'AERO_HOTELS'
                    entry_site = target_entry.get('siteCategory', 'PATROUILLE').upper()
                    if entry_site == 'AERO': entry_site = 'AERO_HOTELS'

                    if entry_site != user_site and self.current_session['role'] != 'SUPERVISEUR':
                        log_audit("CROSS_SITE_UPDATE", self.current_session['email'], client_ip, f"Attempted update on {entry_site} from {user_site}")
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Strict server-side isolation — Cross-perimeter update access denied"}).encode('utf-8'))
                        return

                    editor = self.current_session['email']
                    now_ms = int(1000 * time.time())
                    PROTECTED = ('entryId', 'siteCategory', 'createdBy', 'serverReceivedAt')
                    SIGN_FLAGS = ('agentSigned', 'chefDePosteSigned', 'hdcSigned', 'gphSigned')
                    for k, v in data.items():
                        if k in PROTECTED or k.endswith('SignedBy') or k.endswith('SignedAt'):
                            continue
                        if k in SIGN_FLAGS:
                            if v is True and not target_entry.get(k):
                                target_entry[k] = True
                                target_entry[k + 'By'] = editor
                                target_entry[k + 'At'] = now_ms
                            continue
                        target_entry[k] = v
                    target_entry['siteCategory'] = entry_site
                    save_db()
                    log_audit("MAIN_COURANTE_UPDATE", self.current_session['email'], client_ip, f"Entry {entryId}")
                    broadcast({"type": "MAIN_COURANTE_UPDATED", "entry": target_entry}, target_site=entry_site)
                    self.send_json({"status": "OK", "entry": target_entry})
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            traceback.print_exc()
            self.send_response(500)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ERROR", "message": str(e)}).encode('utf-8'))

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            client_ip = self.client_address[0]

            if path in ['/health', '/api/health', '/api/login'] or path == '/ws':
                if path == '/ws':
                    self.handle_websocket()
                elif path in ['/health', '/api/health']:
                    db_status = "OK"
                    audit_status = "OK" if os.access(AUDIT_LOG_FILE, os.W_OK) or not os.path.exists(AUDIT_LOG_FILE) else "ERROR"
                    media_status = "OK" if os.access(MEDIA_DIR, os.W_OK) or SUPABASE_URL else "ERROR"
                    with db_lock:
                        total_ag = len(agents)
                        now_ms = int(1000 * time.time())
                        online_ag = sum(1 for ag in agents.values() if compute_agent_status(ag.get("lastConnection", now_ms)) == "EN_LIGNE")
                        lost_ag = sum(1 for ag in agents.values() if compute_agent_status(ag.get("lastConnection", now_ms)) == "PERDU")
                        offline_ag = sum(1 for ag in agents.values() if compute_agent_status(ag.get("lastConnection", now_ms)) == "HORS_LIGNE")
                    self.send_json({
                        "status": "HEALTHY" if db_status == "OK" and audit_status == "OK" else "DEGRADED",
                        "service": "PHARE 2.0 Backend",
                        "database": db_status,
                        "audit_log": audit_status,
                        "media_dir": media_status,
                        "agents": {
                            "total": total_ag,
                            "online": online_ag,
                            "lost": lost_ag,
                            "offline": offline_ag
                        },
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                        "uptime": time.time() - server_start_time
                    })
                return

            if not users:
                self.send_response(503)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": "Créez un compte avec python server.py --add-user"}).encode('utf-8'))
                return

            if not self.authenticate_request():
                return

            allowed, code, msg = check_access(self.current_session, path, "GET", client_ip=client_ip)
            if not allowed:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ERROR", "message": msg}).encode('utf-8'))
                return

            if path == '/api/supervisor/config-status':
                with db_lock:
                    sup_auth = db.get("supervisor_auth")
                    is_configured = bool(sup_auth and sup_auth.get("hash"))
                self.send_json({"isConfigured": is_configured})
            elif path == '/api/agents':
                query_params = parse_qs(parsed.query)
                all_flag = query_params.get("all", ["0"])[0] == "1"
                requested_site = query_params.get("siteCategory", [None])[0] or self.headers.get("X-Site-Category")
                user_site = self.current_session['site'].upper()
                if user_site == 'AERO': user_site = 'AERO_HOTELS'

                if requested_site:
                    req_site = requested_site.upper()
                    if req_site == 'AERO': req_site = 'AERO_HOTELS'
                    if user_site != 'TOUS' and req_site != user_site:
                        log_audit("CROSS_SITE_READ", self.current_session['email'], client_ip, f"User {user_site} explicitly queried site {req_site} on {path}")

                now_ms = int(1000 * time.time())
                with db_lock:
                    result_agents = []
                    for ag in agents.values():
                        last_conn = ag.get("lastConnection", now_ms)
                        ag["status"] = compute_agent_status(last_conn)
                        if not all_flag and (now_ms - last_conn > 86400 * 1000):
                            continue

                        if self.current_session['role'] == 'SUPERVISEUR' and user_site != 'TOUS':
                            ag_site = ag.get("siteCategory", "PATROUILLE").upper()
                            if ag_site == 'AERO': ag_site = 'AERO_HOTELS'
                            if ag_site != user_site:
                                continue

                        result_agents.append(ag)
                    self.send_json(result_agents)
            elif path == '/api/events':
                with db_lock:
                    self.send_json(events)
            elif path.startswith('/api/main-courante/events'):
                query_params = parse_qs(parsed.query)
                requested_site = query_params.get("siteCategory", [None])[0] or self.headers.get("X-Site-Category")
                user_site = self.current_session['site'].upper()
                if user_site == 'AERO': user_site = 'AERO_HOTELS'

                if requested_site:
                    req_site = requested_site.upper()
                    if req_site == 'AERO': req_site = 'AERO_HOTELS'
                    if user_site != 'TOUS' and req_site != user_site:
                        log_audit("CROSS_SITE_READ", self.current_session['email'], client_ip, f"User {user_site} explicitly queried site {req_site} on {path}")

                with db_lock:
                    filtered = []
                    for e in main_courante_events:
                        e_site = e.get('siteCategory', 'PATROUILLE').upper()
                        if e_site == 'AERO': e_site = 'AERO_HOTELS'
                        if user_site == 'TOUS' or e_site == user_site or (user_site == 'AERO_HOTELS' and e_site == 'AERO'):
                            filtered.append(e)
                    self.send_json(filtered)
            elif path.startswith('/api/media/'):
                parsed_url = urlparse(path)
                filename = parsed_url.path.split('/')[-1]
                filename = os.path.basename(filename)

                user_site = self.current_session['site'].upper()
                if user_site == 'AERO': user_site = 'AERO_HOTELS'

                with db_lock:
                    media_site = media_categories.get(filename, 'PATROUILLE').upper()
                    if media_site == 'AERO': media_site = 'AERO_HOTELS'

                    if media_site and user_site != 'TOUS' and user_site != media_site:
                        log_audit("CROSS_SITE_READ", self.current_session['email'], client_ip, f"User {user_site} accessed media from {media_site}")
                        self.send_response(403)
                        self.send_header('Content-Type', 'application/json; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(json.dumps({"status": "ERROR", "message": "Forbidden: Strict server-side isolation — Cross-perimeter media access denied"}).encode('utf-8'))
                        return

                file_data = get_media_from_supabase(filename)
                if not file_data:
                    file_path = os.path.join(MEDIA_DIR, filename)
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as f:
                            file_data = f.read()

                if file_data is not None:
                    content_type = "image/jpeg" if filename.endswith((".jpg", ".jpeg", ".png")) else "video/mp4"
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', len(file_data))
                    self.end_headers()
                    self.wfile.write(file_data)
                else:
                    self.send_response(404)
                    self.end_headers()
                return
            elif path == '/api/rounds':
                with db_lock:
                    self.send_json(list(rounds.values()))
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            traceback.print_exc()
            self.send_response(500)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ERROR", "message": str(e)}).encode('utf-8'))

    def handle_websocket(self):
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)
        token_list = query_params.get("token", [])
        if not token_list:
            self.send_response(401)
            self.end_headers()
            return

        token = token_list[0]
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        with db_lock:
            session = sessions.get(token_hash)
            if not session or session["expires_at"] < time.time():
                self.send_response(401)
                self.end_headers()
                return
            client_info = session

        ws_key = self.headers.get('Sec-WebSocket-Key')
        if not ws_key:
            self.send_response(400)
            self.end_headers()
            return

        guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_raw = ws_key + guid
        accept_sha1 = hashlib.sha1(accept_raw.encode('utf-8')).digest()
        accept_val = base64.b64encode(accept_sha1).decode('utf-8')

        self.send_response(101, "Switching Protocols")
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept_val)
        self.end_headers()

        conn = self.connection
        with db_lock:
            clients.append((conn, client_info))
        print(f"[SERVER] WebSocket client connected ({client_info.get('email')}, {client_info.get('site')}).")

        try:
            while True:
                data = conn.recv(2)
                if not data:
                    break
                b1 = data[0]
                b2 = data[1]
                opcode = b1 & 0x0F
                masked = (b2 & 0x80) != 0
                payload_len = b2 & 0x7F

                if payload_len == 126:
                    payload_len = int.from_bytes(conn.recv(2), 'big')
                elif payload_len == 127:
                    payload_len = int.from_bytes(conn.recv(8), 'big')

                mask_key = conn.recv(4) if masked else b''
                payload = conn.recv(payload_len) if payload_len > 0 else b''

                if masked:
                    payload = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))

                if opcode == 0x8:
                    break
                elif opcode == 0x9:
                    pong = bytearray([0x8A, len(payload)])
                    pong.extend(payload)
                    conn.sendall(pong)
                elif opcode == 0x1:
                    txt = payload.decode('utf-8')
                    if txt == "PING":
                        conn.sendall(bytearray([0x81, 4]) + b"PONG")
                    else:
                        try:
                            msg = json.loads(txt)
                            if msg.get("type") == "HEARTBEAT":
                                seq = msg.get("seq", 0)
                                email = client_info.get("email")
                                user_rec = users.get(email, {})
                                agent_id = user_rec.get("agentId") or f"agent_{email.split('@')[0].lower()}"
                                now_ms = int(1000 * time.time())
                                with db_lock:
                                    ag = agents.setdefault(agent_id, {
                                        "id": agent_id,
                                        "fullName": email,
                                        "role": client_info.get("role", "AGENT"),
                                        "siteCategory": client_info.get("site", "PATROUILLE")
                                    })
                                    ag["lastConnection"] = now_ms
                                    ag["status"] = compute_agent_status(now_ms)
                                    if msg.get("battery") is not None:
                                        ag["batteryLevel"] = msg.get("battery")
                                    save_db()

                                ack_data = {
                                    "type": "HEARTBEAT_ACK",
                                    "seq": seq,
                                    "serverTimestamp": int(time.time() * 1000)
                                }
                                ack_bytes = json.dumps(ack_data).encode('utf-8')
                                l_len = len(ack_bytes)
                                ack_frame = bytearray([0x81])
                                if l_len <= 125:
                                    ack_frame.append(l_len)
                                elif l_len <= 65535:
                                    ack_frame.append(126)
                                    ack_frame.extend(l_len.to_bytes(2, 'big'))
                                else:
                                    ack_frame.append(127)
                                    ack_frame.extend(l_len.to_bytes(8, 'big'))
                                ack_frame.extend(ack_bytes)
                                conn.sendall(ack_frame)
                        except Exception as e:
                            print(f"[SERVER] Error handling WS message: {e}")
        except Exception:
            pass
        finally:
            with db_lock:
                for i, (c, _) in enumerate(clients):
                    if c == conn:
                        clients.pop(i)
                        break
            print("[SERVER] WebSocket client disconnected.")

    def send_json(self, data):
        response = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

def handle_shutdown(signum, frame):
    log_structured("INFO", "Server", "SHUTDOWN", f"Received signal {signum}, shutting down gracefully...")
    try:
        save_db()
    except Exception as e:
        log_structured("ERROR", "Server", "SHUTDOWN_ERROR", f"Error saving DB during shutdown: {e}")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

if __name__ == '__main__':
    server = ThreadingTCPServer(("", PORT), PhareServerHandler)
    log_structured("INFO", "Server", "STARTUP", f"PHARE 2.0 Security Hardened Server running on port {PORT}")
    print("==================================================")
    print(f"PHARE 2.0 SECURITY HARDENED SERVER RUNNING ON PORT {PORT}")
    print("==================================================")
    server.serve_forever()
