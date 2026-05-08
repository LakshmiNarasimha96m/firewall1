from flask import Flask, request, render_template_string, jsonify, Response
import joblib
from lime.lime_text import LimeTextExplainer
import re
import os
from datetime import datetime
from collections import deque

# -----------------------------
# Load trained model
# -----------------------------
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

try:
    model2 = joblib.load("model2.pkl")
    vectorizer2 = joblib.load("vectorizer2.pkl")
except Exception:
    model2 = None
    vectorizer2 = None

class_names = ["Normal", "Attack"]
explainer = LimeTextExplainer(class_names=class_names)

app = Flask(__name__)

# In-memory alert store (last 200 alerts)
alert_store = deque(maxlen=200)

# -----------------------------
# Core ML helpers
# -----------------------------
def predict_proba(texts):
    X = vectorizer.transform(texts)
    return model.predict_proba(X)

def detect_attack_type(payload, tokens):
    s = payload.lower()
    joined = " ".join([t.lower() for t, _ in tokens])

    if any(k in s for k in ["../", "..\\", "%2e%2e%2f", "%2e%2e\\", "%252e%252e%252f"]):
        return "Directory Traversal"
    if any(k in s for k in ["; ", "&&", "||", "| ", "`", "$(", "cmd.exe", "powershell", "/bin/sh", "/bin/bash"]):
        return "Command Injection"
    if any(k in s for k in ["<script", "</script", "onerror=", "onload=", "javascript:"]):
        return "XSS (Cross-Site Scripting)"
    if any(k in s for k in [" union ", " select ", " or 1=1", "' or '1'='1", "--", "/*", "*/", " drop ", " insert ", " update ", " delete "]):
        return "SQL Injection"
    if any(k in joined for k in ["script", "alert", "onerror", "onload", "3c", "3e"]):
        return "XSS (Cross-Site Scripting)"
    if any(k in joined for k in ["union", "select", " or ", "--", "drop", "insert"]):
        return "SQL Injection"
    return "Generic Injection Attack"

def build_human_explanation(attack_type, tokens, payload):
    tokens_sorted = sorted(tokens, key=lambda x: abs(x[1]), reverse=True)
    important = [t for t, w in tokens_sorted[:5]]
    if not important:
        s = payload.lower()
        if "<script" in s:
            important = ["<script>", "javascript"]
        elif "../" in s:
            important = ["../"]
        elif "select" in s:
            important = ["SELECT"]
        elif "&&" in s:
            important = ["&&"]
        else:
            important = ["suspicious input"]

    if attack_type.startswith("XSS"):
        return ("The request was classified as an XSS attack because it contains "
                "script-related patterns such as: " + ", ".join(important) +
                ". These indicate injected JavaScript code.")
    if attack_type.startswith("SQL"):
        return ("The request was classified as a SQL Injection attack because it contains "
                "SQL-related patterns such as: " + ", ".join(important) +
                ". These indicate manipulation of database queries.")
    if attack_type.startswith("Directory Traversal"):
        return ("The request was classified as a Directory Traversal attack because it contains "
                "path traversal patterns such as: " + ", ".join(important) +
                ". These may attempt to access sensitive files.")
    if attack_type.startswith("Command Injection"):
        return ("The request was classified as a Command Injection attack because it contains "
                "shell/control operator patterns such as: " + ", ".join(important) +
                ". These may attempt to execute system commands.")
    return ("The request was classified as an injection attack because suspicious "
            "input patterns were detected: " + ", ".join(important))

def run_ml_check(payload):
    """Run ML check and return result dict. Shared by all endpoints."""
    if len(payload.strip()) < 3:
        return {"block": False, "reason": "Input is too short to be considered an attack."}
    if re.fullmatch(r"[a-zA-Z\s]+", payload.strip()):
        return {"block": False, "reason": "Input contains only plain text."}

    X = vectorizer.transform([payload])
    probs = model.predict_proba(X)[0]
    attack_prob = probs[1]
    THRESHOLD = 0.80

    exp = explainer.explain_instance(payload, predict_proba, num_features=10)
    tokens = exp.as_list()

    if attack_prob >= THRESHOLD:
        attack_type = detect_attack_type(payload, tokens)
        explanation = build_human_explanation(attack_type, tokens, payload)
        return {
            "block": True,
            "attack_type": attack_type,
            "confidence": float(attack_prob),
            "explanation": explanation
        }
    else:
        return {
            "block": False,
            "confidence": float(probs[0]),
            "reason": "The input does not match known attack patterns."
        }

# ============================================================
# ADMIN DASHBOARD HTML
# ============================================================
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Admin - Attack Alerts</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; }
  header { background: #1a1d27; border-bottom: 2px solid #e53e3e; padding: 18px 32px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 1.4rem; color: #fff; flex: 1; }
  .hbadge { background: #e53e3e; color: #fff; border-radius: 999px; padding: 2px 14px; font-size: 0.85rem; font-weight: 700; }
  .hbadge.green { background: #38a169; }
  .live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #38a169; margin-right: 5px; animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
  .stats { display: flex; gap: 16px; padding: 24px 32px; flex-wrap: wrap; }
  .stat-card { background: #1a1d27; border-radius: 10px; padding: 18px 24px; flex: 1; min-width: 140px; border-left: 4px solid #e53e3e; }
  .stat-card.blue  { border-left-color: #3b82f6; }
  .stat-card.orange{ border-left-color: #f59e0b; }
  .stat-card.purple{ border-left-color: #a78bfa; }
  .stat-card h3 { font-size: 1.9rem; font-weight: 800; }
  .stat-card p  { font-size: 0.78rem; color: #888; margin-top: 4px; }
  .container { padding: 0 32px 40px; }
  .controls { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; align-items: center; }
  .controls select, .controls input { background: #1a1d27; border: 1px solid #333; color: #e0e0e0; padding: 8px 12px; border-radius: 6px; font-size: 0.88rem; }
  .controls button { background: #e53e3e; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 0.88rem; }
  .controls button.sec { background: #333; }
  .refresh-info { color: #555; font-size: 0.78rem; margin-left: auto; }
  table { width: 100%; border-collapse: collapse; background: #1a1d27; border-radius: 10px; overflow: hidden; font-size: 0.87rem; }
  th { background: #12151f; color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 11px 14px; text-align: left; }
  td { padding: 11px 14px; border-bottom: 1px solid #252833; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #20243a; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 0.73rem; font-weight: 700; }
  .badge-xss { background: #7c3aed22; color: #a78bfa; border: 1px solid #7c3aed55; }
  .badge-sql { background: #b4530022; color: #fb923c; border: 1px solid #b4530055; }
  .badge-dir { background: #0e449922; color: #60a5fa; border: 1px solid #0e449955; }
  .badge-cmd { background: #7f1d1d22; color: #f87171; border: 1px solid #7f1d1d55; }
  .badge-gen { background: #71717a22; color: #d4d4d8; border: 1px solid #71717a55; }
  .payload-cell { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; color: #f87171; font-size: 0.8rem; }
  .expl-cell { max-width: 320px; color: #9ca3af; font-size: 0.8rem; line-height: 1.5; }
  .conf { font-weight: 700; color: #f59e0b; }
  .src-badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 0.7rem; background: #1e2235; border: 1px solid #333; color: #9ca3af; }
  .empty-state { text-align: center; padding: 60px; color: #555; }
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; WAF Admin &mdash; Attack Alert Dashboard</h1>
  <span class="hbadge" id="total-badge">0 alerts</span>
  <span class="hbadge green"><span class="live-dot"></span>Live</span>
</header>

<div class="stats">
  <div class="stat-card"       id="stat-total"><h3>0</h3><p>Total Attacks Blocked</p></div>
  <div class="stat-card blue"  id="stat-xss"  ><h3>0</h3><p>XSS Attacks</p></div>
  <div class="stat-card orange"id="stat-sql"  ><h3>0</h3><p>SQL Injections</p></div>
  <div class="stat-card purple"id="stat-other"><h3>0</h3><p>Other Attacks</p></div>
</div>

<div class="container">
  <div class="controls">
    <select id="filter-type" onchange="applyFilter()">
      <option value="">All Types</option>
      <option value="XSS">XSS</option>
      <option value="SQL">SQL Injection</option>
      <option value="Directory">Directory Traversal</option>
      <option value="Command">Command Injection</option>
      <option value="Generic">Generic Injection</option>
    </select>
    <input type="text" id="search-payload" placeholder="Search payload..." oninput="applyFilter()" style="width:220px">
    <button onclick="loadAlerts()">&#x1F504; Refresh</button>
    <button class="sec" onclick="clearAlerts()">&#x1F5D1; Clear All</button>
    <span class="refresh-info" id="last-refresh">Auto-refresh every 10s</span>
  </div>

  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Timestamp (UTC)</th>
        <th>Attack Type</th>
        <th>Payload</th>
        <th>Confidence</th>
        <th>Source</th>
        <th>AI Explanation</th>
      </tr>
    </thead>
    <tbody id="alerts-body">
      <tr><td colspan="7" class="empty-state">Loading alerts...</td></tr>
    </tbody>
  </table>
</div>

<script>
let allAlerts = [];

function getBadgeClass(type) {
  if (!type) return 'badge-gen';
  if (type.includes('XSS')) return 'badge-xss';
  if (type.includes('SQL')) return 'badge-sql';
  if (type.includes('Directory')) return 'badge-dir';
  if (type.includes('Command')) return 'badge-cmd';
  return 'badge-gen';
}

function esc(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function applyFilter() {
  const tf = document.getElementById('filter-type').value.toLowerCase();
  const pf = document.getElementById('search-payload').value.toLowerCase();
  const filtered = allAlerts.filter(a => {
    return (!tf || (a.attack_type||'').toLowerCase().includes(tf)) &&
           (!pf || (a.payload||'').toLowerCase().includes(pf));
  });
  renderAlerts(filtered);
}

function renderAlerts(alerts) {
  const tbody = document.getElementById('alerts-body');
  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">&#x1F6E1; No attacks detected yet.</td></tr>';
    return;
  }
  const rows = alerts.slice().reverse();
  tbody.innerHTML = rows.map((a, i) => `
    <tr>
      <td style="color:#555">${alerts.length - i}</td>
      <td style="white-space:nowrap;color:#6b7280;font-size:0.78rem">${esc(a.timestamp||'')}</td>
      <td><span class="badge ${getBadgeClass(a.attack_type)}">${esc(a.attack_type||'Unknown')}</span></td>
      <td class="payload-cell" title="${esc(a.payload||'')}">${esc(a.payload||'&mdash;')}</td>
      <td class="conf">${a.confidence ? (a.confidence*100).toFixed(1)+'%' : '&mdash;'}</td>
      <td><span class="src-badge">${esc(a.source||'direct')}</span></td>
      <td class="expl-cell">${esc(a.explanation||'&mdash;')}</td>
    </tr>
  `).join('');
}

function updateStats(alerts) {
  document.getElementById('total-badge').textContent = alerts.length + ' alert' + (alerts.length!==1?'s':'');
  document.getElementById('stat-total').querySelector('h3').textContent = alerts.length;
  document.getElementById('stat-xss').querySelector('h3').textContent = alerts.filter(a=>(a.attack_type||'').includes('XSS')).length;
  document.getElementById('stat-sql').querySelector('h3').textContent = alerts.filter(a=>(a.attack_type||'').includes('SQL')).length;
  document.getElementById('stat-other').querySelector('h3').textContent = alerts.filter(a=>!(a.attack_type||'').includes('XSS')&&!(a.attack_type||'').includes('SQL')).length;
}

async function loadAlerts() {
  try {
    const res = await fetch('/admin/alerts');
    const data = await res.json();
    allAlerts = data.alerts || [];
    updateStats(allAlerts);
    applyFilter();
    document.getElementById('last-refresh').textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('alerts-body').innerHTML = '<tr><td colspan="7" class="empty-state" style="color:#e53e3e">Error loading alerts. Check server.</td></tr>';
  }
}

async function clearAlerts() {
  if (!confirm('Clear all alerts from memory?')) return;
  await fetch('/admin/alerts', { method: 'DELETE' });
  loadAlerts();
}

loadAlerts();
setInterval(loadAlerts, 10000);
</script>
</body>
</html>
"""

# ============================================================
# UI (manual testing)
# ============================================================
HTML = """
<!DOCTYPE html>
<html>
<head><title>Explainable AI - Web Attack Detection</title></head>
<body>
    <h2>Explainable AI - Web Attack Detection</h2>
    <p><a href="/admin">Go to Admin Alert Dashboard</a></p>
    <form method="POST">
        <input type="text" name="payload" size="90" required>
        <br><br>
        <button type="submit">Check</button>
    </form>
    {% if result %}
        <h3>{{ result }}</h3>
        <p><b>Explanation:</b></p>
        <p>{{ explanation }}</p>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    explanation = None
    if request.method == "POST":
        payload = request.form.get("payload", "")
        res = run_ml_check(payload)
        if res["block"]:
            result = "ATTACK DETECTED : {} (confidence: {:.2f})".format(res['attack_type'], res['confidence'])
            explanation = res["explanation"]
            alert_store.append({
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "attack_type": res["attack_type"],
                "confidence": res["confidence"],
                "explanation": res["explanation"],
                "payload": payload,
                "source": "manual-ui"
            })
        else:
            conf = res.get('confidence', 0)
            result = "NORMAL INPUT (confidence: {:.2f})".format(conf)
            explanation = res.get("reason", "The input does not match known attack patterns.")
    return render_template_string(HTML, result=result, explanation=explanation)


# ============================================================
# WAF API -- called by the web app (Node.js)
# ============================================================
@app.route("/api/waf", methods=["POST"])
def waf_api():
    """
    Expects: {"payload": "...", "source": "search|login|register"}
    Returns: {"block": true/false, "attack_type": ..., "confidence": ..., "explanation": ...}
    """
    data = request.get_json(silent=True)
    if not data or "payload" not in data:
        return jsonify({"block": False, "error": "No payload provided"}), 400

    payload = data["payload"]
    source = data.get("source", "web-app")

    res = run_ml_check(payload)

    if res["block"]:
        alert_store.append({
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "attack_type": res["attack_type"],
            "confidence": res["confidence"],
            "explanation": res["explanation"],
            "payload": payload,
            "source": source
        })

    return jsonify(res)


# ============================================================
# NOTIFICATION endpoint (extra: web app can push alerts here)
# ============================================================
@app.route("/api/notify", methods=["POST"])
def notify():
    """
    Receives pre-built alert notifications from the web app.
    Body: {attack_type, confidence, explanation, payload, source}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "No data"}), 400

    alert_store.append({
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "attack_type": data.get("attack_type", "Unknown"),
        "confidence": data.get("confidence", 0),
        "explanation": data.get("explanation", ""),
        "payload": data.get("payload", ""),
        "source": data.get("source", "web-app-notify")
    })
    return jsonify({"status": "ok", "total_alerts": len(alert_store)})


# ============================================================
# ADMIN DASHBOARD
# ============================================================
@app.route("/admin")
def admin():
    return render_template_string(ADMIN_HTML)

@app.route("/admin/alerts", methods=["GET"])
def get_alerts():
    return jsonify({"alerts": list(alert_store), "total": len(alert_store)})

@app.route("/admin/alerts", methods=["DELETE"])
def clear_alerts():
    alert_store.clear()
    return jsonify({"status": "cleared"})


# ============================================================
# CORS -- allow the Vercel web app to call this firewall
# ============================================================
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response

@app.route("/api/waf", methods=["OPTIONS"])
def waf_options():
    return Response(status=200)

@app.route("/api/notify", methods=["OPTIONS"])
def notify_options():
    return Response(status=200)


# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
