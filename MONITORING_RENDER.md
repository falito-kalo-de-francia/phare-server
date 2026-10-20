# GUIDE DE SURVEILLANCE & MAINTENANCE RENDER — PHARE 2.0

Ce document détaille la configuration du monitoring UptimeRobot pour l'endpoint `/health` ainsi que la gestion des contraintes du plan gratuit Render (Render Free) et leur mitigation pour assurer une activité de maintenance et un fonctionnement continu sur 12 heures.

---

## 1. Contraintes de l'Offre Gratuite Render (Render Free) & Mitigations

| Contrainte Render Free | Impact potentiellement observé | Stratégie de Mitigation PHARE 2.0 |
| :--- | :--- | :--- |
| **Mise en veille (Spin-down)** après 15 minutes d'inactivité HTTP entrante. | Le serveur s'endort, entraînant une latence au réveil (cold start) ou une déconnexion temporaire des WebSockets. | **Ping UptimeRobot automatique** toutes les 5 minutes sur `/health` pour maintenir l'instance active en permanence. |
| **Système de fichiers éphémère** (perte des données locales non montées sur disque lors d'un redémarrage/redéploiement). | Risque de perte de la base de données JSON ou des fichiers médias uploadés. | <ul><li>Sauvegarde atomique (`save_db()` via fichier `.tmp` + `os.replace`) dans `server.py`.</li><li>Utilisation d'un **Render Disk** monté sur `/app/media_uploads` et persistance de `phare_server_db.json`.</li></ul> |
| **Quota de 750 heures gratuites** par mois. | Arrêt du service en fin de mois si une seule instance tourne 24h/24 sans optimisation. | Une seule instance active (suffisante pour la couverture opérationnelle 12h de patrouille). |

---

## 2. Configuration d'UptimeRobot pour le Health Check (`/health`)

Pour empêcher la mise en veille de l'instance Render et surveiller la santé du backend PHARE 2.0 en continu :

1. **Création d'un compte** sur [UptimeRobot](https://uptimerobot.com).
2. Cliquer sur **Add New Monitor**.
3. Configurer le moniteur :
   - **Monitor Type** : `HTTP(s)`
   - **Friendly Name** : `PHARE 2.0 Backend Health`
   - **URL (or IP)** : `https://<votre-service>.onrender.com/health` (ou `/api/health`)
   - **Monitoring Interval** : `5 minutes` (recommandé pour maintenir le service éveillé avant le délai de spin-down de 15 minutes).
   - **Keyword/Response Validation** : Vérifier la présence du mot clé `HEALTHY` ou du statut JSON `{"status":"HEALTHY"}`.
4. Configurer les alertes (Email, Webhook, SMS, etc.) en cas de panne (code HTTP différent de 200 ou échec du health check).

---

## 3. Architecture du Module de Heartbeat & Reconnexion PHARE 2.0

### Backend (`server.py`)
- Expose **`GET /health`** retournant un statut JSON enrichi :
  ```json
  {
    "status": "HEALTHY",
    "service": "PHARE 2.0 Backend",
    "database": "OK",
    "audit_log": "OK",
    "media_dir": "OK",
    "agents": {
      "total": 5,
      "online": 4,
      "lost": 1,
      "offline": 0
    },
    "timestamp": "2025-02-28 12:00:00",
    "uptime": 43200.0
  }
  ```
- **WebSocket Heartbeat** : Gère les messages entrants `{"type": "HEARTBEAT", "seq": N}` et répond par un accusé de réception `{"type": "HEARTBEAT_ACK", "seq": N, "serverTimestamp": ...}`.
- **Calcul de présence dynamique** (`compute_agent_status`) :
  - `< 90 secondes` : `EN_LIGNE`
  - `< 600 secondes` : `PERDU`
  - `> 600 secondes` : `HORS_LIGNE`

### Client Android (`PhareWebSocketClient.kt`, `MainViewModel.kt`, `PcSupervisorViewModel.kt`)
- **Agents (60s WebSocket Heartbeat Loop)** : Envoi automatique de `HEARTBEAT` toutes les 60 secondes lorsque l'agent est connecté et actif.
- **Reconnexion Auto avec Backoff Exponentiel et Jitter** : En cas de coupure réseau, tentative de reconnexion progressive (2s, 4s, 8s, 16s, 30s max + jitter) et resynchronisation automatique de la file d'attente (pending queue sync).
- **PC Supervisor (60s Heartbeat & 180s Silence Detection)** :
  - Boucle de battement de cœur 60s active lorsque l'écran de supervision est affiché.
  - **Détection d'absence de signal de 180 secondes** : Marque automatiquement un agent silencieux depuis plus de 3 minutes comme `PERDU` pour déclencher les alertes de supervision.
