#!/usr/bin/env python3
"""Tests automatisés de server.py (PHARE 2.0). Aucune dépendance externe.

Usage :  python test_server.py [chemin/vers/server.py]
Le serveur est lancé dans un dossier temporaire sur le port 18080 (variable
PHARE_PORT) : vos vraies données ne sont jamais touchées.
Code de sortie 0 = tout est passé, 1 = au moins un échec.
"""
import base64, hashlib, json, os, select, shutil, signal, socket
import subprocess, sys, tempfile, time, urllib.request, urllib.error

SERVER = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("server.py")
PORT = int(os.environ.get("PHARE_PORT", "18080"))
BASE = f"http://127.0.0.1:{PORT}"
RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append(bool(condition))
    print(("PASS  " if condition else "FAIL  ") + name + ("" if condition else f"   -> {detail}"))


def make_user(email, password, role, site):
    salt = os.urandom(16)
    return {
        "email": email,
        "password_hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex(),
        "salt": base64.b64encode(salt).decode(),
        "iterations": 100000, "role": role, "site": site,
    }


def start_server(workdir, env_extra=None):
    env = dict(os.environ, PHARE_PORT=str(PORT))
    if env_extra:
        env.update(env_extra)
    log = open(os.path.join(workdir, "server.log"), "a")
    proc = subprocess.Popen([sys.executable, SERVER], cwd=workdir, env=env,
                            stdout=log, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            return proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("le serveur ne démarre pas (voir server.log)")


def stop_server(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def call(method, path, data=None, token=None, headers=None, raw=None):
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(BASE + path, method=method, data=body)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=10)
        txt = r.read().decode()
        code = r.status
    except urllib.error.HTTPError as e:
        txt, code = e.read().decode(), e.code
    try:
        return code, json.loads(txt)
    except Exception:
        return code, txt


def login(email, password):
    code, body = call("POST", "/api/login", {"email": email, "password": password})
    return body.get("token") if code == 200 and isinstance(body, dict) else None


class WS:
    def __init__(self, token=None):
        self.s = socket.create_connection(("127.0.0.1", PORT))
        key = base64.b64encode(os.urandom(16)).decode()
        path = "/ws" + (f"?token={token}" if token else "")
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
        time.sleep(0.4)
        self.status = self.s.recv(4096).split(b"\r\n")[0].decode()

    def messages(self, wait=0.7):
        out = b""
        while select.select([self.s], [], [], wait)[0]:
            chunk = self.s.recv(65536)
            if not chunk:
                break
            out += chunk
        msgs, i = [], 0
        while i < len(out) - 1 and out[i] == 0x81:
            n = out[i + 1]; i += 2
            if n == 126:
                n = int.from_bytes(out[i:i + 2], "big"); i += 2
            msgs.append(json.loads(out[i:i + n])); i += n
        return msgs


def entry(entry_id, site):
    return {"entryId": entry_id, "siteCategory": site, "agentName": "t",
            "eventType": "TEST_" + site, "attachments": []}


def main():
    work = tempfile.mkdtemp(prefix="phare_test_")
    try:
        # ---- 1. démarrage sans aucun compte
        p = start_server(work)
        code, _ = call("POST", "/api/login", {"email": "a@b.c", "password": "x"})
        check("sans compte : login refusé (503)", code == 503, code)
        check("sans compte : /health répond 200", call("GET", "/health")[0] == 200)
        stop_server(p)

        # ---- 2. comptes de test
        users = {e: make_user(e, *a) for e, a in {
            "sup@t.fr": ("superviseur-long-mdp", "SUPERVISEUR", "TOUS"),
            "pat@t.fr": ("pat12345", "AGENT", "PATROUILLE"),
            "pat2@t.fr": ("pat12345", "AGENT", "PATROUILLE"),
            "aero@t.fr": ("aero1234", "AGENT", "AERO_HOTELS"),
            "hot@t.fr": ("hot12345", "AGENT", "HOTELS"),
        }.items()}
        with open(os.path.join(work, "phare_server_db.json"), "w") as f:
            json.dump({"users": users}, f)
        p = start_server(work)

        T = {n: login(e, pw) for n, (e, pw) in {
            "sup": ("sup@t.fr", "superviseur-long-mdp"), "pat": ("pat@t.fr", "pat12345"),
            "pat2": ("pat2@t.fr", "pat12345"), "aero": ("aero@t.fr", "aero1234"),
            "hot": ("hot@t.fr", "hot12345")}.items()}
        check("login des 5 comptes", all(T.values()), T)
        check("sans jeton : 401", call("GET", "/api/main-courante/events")[0] == 401)
        check("aucune ronde par défaut (pas de données factices)",
              call("GET", "/api/rounds", token=T["sup"])[1] == [], call("GET", "/api/rounds", token=T["sup"]))

        # ---- 3. WebSocket
        check("WebSocket sans jeton refusé", "401" in WS(None).status)
        check("WebSocket faux jeton refusé", "401" in WS("faux").status)
        ws_sup, ws_pat2, ws_hot = WS(T["sup"]), WS(T["pat2"]), WS(T["hot"])
        check("WebSocket avec jeton accepté", "101" in ws_sup.status, ws_sup.status)

        # ---- 4. main courante + diffusion
        c, b = call("POST", "/api/main-courante/events", entry("m1", "PATROUILLE"), T["pat"])
        check("POST main courante de son site = 200 (pas 500)", c == 200, (c, b))
        check("POST main courante dans un autre site = 403",
              call("POST", "/api/main-courante/events", entry("m2", "HOTELS"), T["pat"])[0] == 403)
        call("POST", "/api/main-courante/events", entry("m3", "AERO_HOTELS"), T["aero"])
        call("POST", "/api/main-courante/events", entry("m4", "HOTELS"), T["hot"])
        check("même entrée renvoyée = DUPLICATE (pas d'erreur)",
              call("POST", "/api/main-courante/events", entry("m1", "PATROUILLE"), T["pat"])[1].get("status") == "DUPLICATE")
        got_sup = [m.get("entry", {}).get("entryId") for m in ws_sup.messages() if m.get("type") == "MAIN_COURANTE_ADDED"]
        got_pat2 = [m.get("entry", {}).get("entryId") for m in ws_pat2.messages() if m.get("type") == "MAIN_COURANTE_ADDED"]
        got_hot = [m.get("entry", {}).get("entryId") for m in ws_hot.messages() if m.get("type") == "MAIN_COURANTE_ADDED"]
        check("superviseur reçoit les entrées de tous les sites en direct", sorted(got_sup) == ["m1", "m3", "m4"], got_sup)
        check("agent du même site reçoit l'entrée de son site", got_pat2 == ["m1"], got_pat2)
        check("agent d'un autre site ne reçoit pas les entrées des autres", got_hot == ["m4"], got_hot)
        ids = lambda t: sorted(e["entryId"] for e in call("GET", "/api/main-courante/events", token=t)[1])
        check("lecture : superviseur voit tout", ids(T["sup"]) == ["m1", "m3", "m4"], ids(T["sup"]))
        check("lecture : agent ne voit que son site", ids(T["pat"]) == ["m1"] and ids(T["hot"]) == ["m4"])
        check("PUT sur entrée d'un autre site = 403",
              call("PUT", "/api/main-courante/events/m4", {"status": "X"}, T["pat"])[0] == 403)
        check("PUT superviseur = 200", call("PUT", "/api/main-courante/events/m4", {"status": "SIGNE"}, T["sup"])[0] == 200)

        # ---- 5. rôles
        check("agent refusé sur /api/agents", call("GET", "/api/agents", token=T["pat"])[0] == 403)
        check("agent refusé sur /api/events", call("GET", "/api/events", token=T["pat"])[0] == 403)
        check("agent refusé sur acquittement", call("POST", "/api/agents/acknowledge", {"agentId": "a", "eventId": "e"}, T["pat"])[0] == 403)
        check("agent refusé sur /api/rounds (POST)", call("POST", "/api/rounds", {"name": "x"}, T["pat"])[0] == 403)
        check("usurpation de position = 403",
              call("POST", "/api/agents/x/position", {"agentId": "agent_aero", "latitude": 1, "longitude": 1}, T["pat"])[0] == 403)
        call("POST", "/api/agents/x/position", {"latitude": 43.1, "longitude": 5.9, "precision": 5, "battery": 80}, T["aero"])
        check("heartbeat accepté", call("POST", "/api/agents/heartbeat", {}, T["pat"])[0] == 200)
        agents = call("GET", "/api/agents", token=T["sup"])[1]
        by_id = {a["id"]: a for a in agents} if isinstance(agents, list) else {}
        check("superviseur voit les agents connectés avec site et état",
              by_id.get("agent_aero", {}).get("status") == "EN_LIGNE" and by_id.get("agent_pat", {}).get("siteCategory") == "PATROUILLE", by_id)
        check("acquittement par superviseur = 200",
              call("POST", "/api/agents/acknowledge", {"agentId": "agent_aero", "eventId": "e1"}, T["sup"])[0] == 200)

        # ---- 5b. écritures du superviseur (il doit pouvoir écrire sans « voler » l'entrée à l'agent)
        c, b = call("POST", "/api/main-courante/events", entry("s1", "HOTELS"), T["sup"])
        check("superviseur peut écrire une entrée pour un site précis (200)", c == 200, (c, b))
        check("superviseur sans site précisé = 400 (pas de catégorie « TOUS »)",
              call("POST", "/api/main-courante/events", {"entryId": "s2", "eventType": "X", "attachments": []}, T["sup"])[0] == 400)
        hot_ids = lambda: sorted(e["entryId"] for e in call("GET", "/api/main-courante/events", token=T["hot"])[1])
        check("l'agent du site voit l'entrée écrite par le superviseur", "s1" in hot_ids(), hot_ids())
        call("PUT", "/api/main-courante/events/m4", {"status": "VU_PAR_SUPERVISEUR"}, T["sup"])
        check("après modification par le superviseur, l'agent voit toujours son entrée", "m4" in hot_ids(), hot_ids())
        m4 = [e for e in call("GET", "/api/main-courante/events", token=T["sup"])[1] if e["entryId"] == "m4"]
        check("le site de l'entrée n'est jamais changé en « TOUS »", m4 and m4[0]["siteCategory"] == "HOTELS", m4)
        call("PUT", "/api/main-courante/events/m4", {"agentSigned": True}, T["hot"])
        call("PUT", "/api/main-courante/events/m4", {"agentSigned": False, "siteCategory": "PATROUILLE", "agentSignedBy": "usurpateur"}, T["hot"])
        m4 = [e for e in call("GET", "/api/main-courante/events", token=T["sup"])[1] if e["entryId"] == "m4"][0]
        check("signature : enregistrée avec le compte réel et l'heure du serveur",
              m4.get("agentSigned") is True and m4.get("agentSignedBy") == "hot@t.fr" and isinstance(m4.get("agentSignedAt"), int), m4)
        check("signature : impossible à retirer ou à falsifier", m4.get("agentSigned") is True and m4.get("siteCategory") == "HOTELS" and m4.get("agentSignedBy") == "hot@t.fr", m4)
        c, b = call("POST", "/api/main-courante/upload", token=T["sup"], raw=b"VIDEO")
        check("upload superviseur sans site précisé = 400", c == 400, (c, b))
        c, b = call("POST", "/api/main-courante/upload", token=T["sup"], headers={"X-Site-Category": "HOTELS"}, raw=b"VIDEO")
        fn2 = b.get("filename", "") if isinstance(b, dict) else ""
        check("média du superviseur lisible par les agents du site visé", c == 200 and call("GET", "/api/media/" + fn2, token=T["hot"])[0] == 200, (c, b))

        # ---- 6. PIN superviseur
        check("PIN non configuré -> 400", call("POST", "/api/supervisor/auth", {"pin": "123456"}, T["sup"])[0] == 400)
        check("agent ne peut pas configurer le PIN", call("POST", "/api/supervisor/setup", {"pin": "123456"}, T["pat"])[0] == 403)
        check("superviseur configure le PIN", call("POST", "/api/supervisor/setup", {"pin": "123456"}, T["sup"])[0] == 200)
        check("rondes refusées sans PIN valide récent", call("POST", "/api/rounds", {"name": "r"}, T["sup"])[0] == 403)
        check("mauvais PIN = 401", call("POST", "/api/supervisor/auth", {"pin": "000000"}, T["sup"])[0] == 401)
        check("bon PIN = 200", call("POST", "/api/supervisor/auth", {"pin": "123456"}, T["sup"])[0] == 200)
        check("rondes acceptées après PIN", call("POST", "/api/rounds", {"name": "r", "points": []}, T["sup"])[0] == 200)

        # ---- 7. médias
        c, b = call("POST", "/api/main-courante/upload", token=T["pat"], headers={"X-Filename": "../../x.jpg"}, raw=b"JPEGDATA")
        fn = b.get("filename", "") if isinstance(b, dict) else ""
        check("upload : nom généré par le serveur, sans '..'", c == 200 and ".." not in fn and "/" not in fn and fn.endswith(".jpg"), (c, b))
        check("média lisible par son site", call("GET", "/api/media/" + fn, token=T["pat"])[0] == 200)
        check("média lisible par le superviseur", call("GET", "/api/media/" + fn, token=T["sup"])[0] == 200)
        check("média refusé à un autre site", call("GET", "/api/media/" + fn, token=T["hot"])[0] == 403)
        s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(5)
        s.sendall((f"POST /api/main-courante/upload HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {T['pat']}\r\n"
                   f"Content-Length: {16 * 1024 * 1024}\r\n\r\n").encode())
        check("upload de 16 Mo refusé (413)", b" 413 " in s.recv(200).split(b"\r\n")[0] + b" ")

        # ---- 8. journal d'audit
        audit_path = os.path.join(work, "audit.log")
        count = lambda: (open(audit_path).read() if os.path.exists(audit_path) else "").count("CROSS_SITE_READ")
        before = count()
        call("GET", "/api/main-courante/events", token=T["pat"])
        check("audit : lecture normale d'un agent ne crée pas de CROSS_SITE_READ", count() == before, (before, count()))
        call("GET", "/api/main-courante/events?siteCategory=HOTELS", token=T["pat"])
        check("audit : demande explicite d'un autre site = CROSS_SITE_READ", count() == before + 1, (before, count()))

        # ---- 9. verrouillage
        codes = [call("POST", "/api/login", {"email": "aero@t.fr", "password": "mauvais"})[0] for _ in range(6)]
        check("5 mauvais mots de passe puis 429", codes[:5] == [401] * 5 and codes[5] == 429, codes)
        check("un autre compte n'est pas bloqué", login("hot@t.fr", "hot12345") is not None)

        # ---- 10. redémarrage
        stop_server(p)
        p = start_server(work)
        check("jeton toujours valide après redémarrage du serveur",
              call("GET", "/api/main-courante/events", token=T["sup"])[0] == 200)
        db_txt = open(os.path.join(work, "phare_server_db.json")).read()
        check("jetons stockés hachés (jamais en clair)", not any(t in db_txt for t in T.values() if t))
        check("aucun traceback dans le journal du serveur",
              "Traceback" not in open(os.path.join(work, "server.log")).read(),
              "voir server.log")
        stop_server(p)

        # ---- 11. admin bootstrap depuis l'environnement
        work_adm = tempfile.mkdtemp(prefix="phare_adm_")
        try:
            p_adm = start_server(work_adm, env_extra={"PHARE_ADMIN_EMAIL": "admin@env.fr", "PHARE_ADMIN_PASSWORD": "adminsecurepassword123"})
            check("admin bootstrap depuis l'environnement : login réussi", login("admin@env.fr", "adminsecurepassword123") is not None)
            stop_server(p_adm)
        finally:
            shutil.rmtree(work_adm, ignore_errors=True)

        # ---- 12. endpoint /api/bootstrap
        work_boot = tempfile.mkdtemp(prefix="phare_boot_")
        try:
            p_boot = start_server(work_boot, env_extra={"PHARE_SETUP_TOKEN": "secret123"})
            c, b = call("POST", "/api/bootstrap", {"email": "boot@env.fr", "password": "bootsecurepassword123"}, headers={"X-Setup-Token": "secret123"})
            check("POST /api/bootstrap superviseur initial = 200", c == 200, (c, b))
            check("login après /api/bootstrap réussi", login("boot@env.fr", "bootsecurepassword123") is not None)
            stop_server(p_boot)
        finally:
            shutil.rmtree(work_boot, ignore_errors=True)

        # ---- 13. PostgreSQL outage / invalid URL raises exception at startup
        work_pg = tempfile.mkdtemp(prefix="phare_pg_")
        try:
            pg_failed = False
            try:
                p_pg = start_server(work_pg, env_extra={"DATABASE_URL": "postgresql://invalid:invalid@127.0.0.1:5432/invalid"})
                stop_server(p_pg)
            except RuntimeError:
                pg_failed = True
            check("PostgreSQL invalide lève une exception au démarrage (pas de DB vide silencieuse)", pg_failed)
        finally:
            shutil.rmtree(work_pg, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed, total = sum(RESULTS), len(RESULTS)
    print(f"\n{passed}/{total} tests réussis")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
