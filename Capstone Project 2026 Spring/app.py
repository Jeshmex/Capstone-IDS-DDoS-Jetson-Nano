# =============================================================
# app.py
# AI-Based DDoS IDS - Web Dashboard
# Jeshua Vargas Valenzuela - CSC 520
#
# Run on Jetson Orin Nano:
#   python3 app.py
#
# Then open browser on any device on the network:
#   http://JETSON_IP:5000
# =============================================================

import os
import joblib
import numpy as np
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# =============================================================
# In-memory state
# =============================================================

alert_log = []
stats     = {
    'total':   0,
    'attacks': 0,
    'benign':  0,
}

# =============================================================
# Load models at startup (for /api/predict endpoint)
# =============================================================

base = os.path.dirname(os.path.abspath(__file__))

try:
    model        = joblib.load(os.path.join(base, 'best_model.pkl'))
    scaler       = joblib.load(os.path.join(base, 'scaler.pkl'))
    imputer      = joblib.load(os.path.join(base, 'imputer.pkl'))
    le           = joblib.load(os.path.join(base, 'label_encoder.pkl'))
    feature_cols = joblib.load(os.path.join(base, 'feature_columns.pkl'))
    print(f"[Dashboard] Models loaded: {len(le.classes_)} classes")
    print(f"[Dashboard] Classes: {le.classes_.tolist()}")
except Exception as e:
    print(f"[Dashboard] WARNING: Could not load models: {e}")
    model = scaler = imputer = le = feature_cols = None


# =============================================================
# HTML Dashboard
# =============================================================

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI DDoS Detection Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Rajdhani', sans-serif;
            background: #060a0f;
            color: #a8c8e8;
            min-height: 100vh;
            padding: 24px;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background-image:
                linear-gradient(rgba(0,180,255,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,180,255,0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            position: relative;
            z-index: 1;
            max-width: 1300px;
            margin: 0 auto;
        }

        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 32px;
            padding-bottom: 16px;
            border-bottom: 1px solid rgba(0,180,255,0.2);
        }

        .logo {
            font-family: 'Share Tech Mono', monospace;
            font-size: 1em;
            color: #00b4ff;
            letter-spacing: 2px;
        }

        h1 {
            font-size: 1.7em;
            font-weight: 700;
            color: #e0f0ff;
            letter-spacing: 1px;
        }

        .status {
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.78em;
            padding: 6px 14px;
            border-radius: 4px;
            background: rgba(0,255,100,0.08);
            border: 1px solid rgba(0,255,100,0.3);
            color: #00ff64;
            letter-spacing: 1px;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }

        .card {
            background: rgba(0,20,40,0.8);
            border: 1px solid rgba(0,180,255,0.15);
            border-radius: 8px;
            padding: 22px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg,
                transparent, #00b4ff, transparent);
        }

        .card h2 {
            font-family: 'Share Tech Mono', monospace;
            font-size: 2.6em;
            color: #00b4ff;
            margin-bottom: 6px;
        }

        .card p {
            font-size: 0.82em;
            color: #5a7a98;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .card.red    h2 { color: #ff4444; }
        .card.orange h2 { color: #ff8800; }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .section-header h2 {
            font-size: 1.1em;
            font-weight: 700;
            color: #e0f0ff;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .refresh-note {
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.72em;
            color: #2a4a68;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(0,15,35,0.7);
            border: 1px solid rgba(0,180,255,0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        th {
            background: rgba(0,30,70,0.9);
            padding: 12px 16px;
            text-align: left;
            font-size: 0.75em;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #00b4ff;
            font-weight: 700;
        }

        td {
            padding: 11px 16px;
            border-bottom: 1px solid rgba(0,180,255,0.05);
            font-size: 0.9em;
            font-family: 'Share Tech Mono', monospace;
            color: #8ab8d8;
        }

        tr:hover td { background: rgba(0,180,255,0.03); }
        tr:last-child td { border-bottom: none; }

        .empty {
            text-align: center;
            padding: 48px;
            color: #2a4a68;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.88em;
        }

        .badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 3px;
            font-size: 0.78em;
            font-weight: 700;
            letter-spacing: 1px;
        }

        .CRITICAL {
            background: rgba(255,68,68,0.12);
            border: 1px solid rgba(255,68,68,0.35);
            color: #ff4444;
        }
        .HIGH {
            background: rgba(255,136,0,0.12);
            border: 1px solid rgba(255,136,0,0.35);
            color: #ff8800;
        }
        .MEDIUM {
            background: rgba(255,204,0,0.12);
            border: 1px solid rgba(255,204,0,0.35);
            color: #ffcc00;
        }
        .LOW {
            background: rgba(0,255,100,0.08);
            border: 1px solid rgba(0,255,100,0.25);
            color: #00e664;
        }
    </style>
</head>
<body>
<div class="container">

    <header>
        <div class="logo">SECUREMENT v2.0 // JETSON ORIN NANO</div>
        <h1>AI-Powered DDoS Detection Dashboard</h1>
        <div class="status">MONITORING ACTIVE</div>
    </header>

    <div class="cards">
        <div class="card">
            <h2>{{ stats.total }}</h2>
            <p>Total Flows</p>
        </div>
        <div class="card red">
            <h2>{{ stats.attacks }}</h2>
            <p>Attacks Detected</p>
        </div>
        <div class="card">
            <h2>{{ stats.benign }}</h2>
            <p>Benign Flows</p>
        </div>
        <div class="card orange">
            <h2>{{ attack_rate }}%</h2>
            <p>Attack Rate</p>
        </div>
    </div>

    <div class="section-header">
        <h2>Recent Alerts</h2>
        <span class="refresh-note">AUTO-REFRESH EVERY 5s</span>
    </div>

    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Attack Type</th>
                <th>Confidence</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
            {% if alerts %}
                {% for a in alerts %}
                <tr>
                    <td>{{ a.timestamp }}</td>
                    <td>{{ a.src_ip }}</td>
                    <td>{{ a.attack_type }}</td>
                    <td>{{ a.confidence }}</td>
                    <td>
                        <span class="badge {{ a.severity }}">
                            {{ a.severity }}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            {% else %}
                <tr>
                    <td colspan="5" class="empty">
                        No alerts yet. System is monitoring network traffic...
                    </td>
                </tr>
            {% endif %}
        </tbody>
    </table>

</div>

<script>
    // Auto-refresh every 5 seconds
    setTimeout(function() { location.reload(); }, 5000);
</script>
</body>
</html>
"""


# =============================================================
# Routes
# =============================================================

@app.route('/')
def dashboard():
    total       = stats['total']
    attack_rate = round(
        stats['attacks'] / total * 100, 2
    ) if total > 0 else 0
    recent = list(reversed(alert_log[-50:]))
    return render_template_string(
        HTML,
        stats       = stats,
        attack_rate = attack_rate,
        alerts      = recent
    )


@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """Receives alerts pushed from ids_engine.py"""
    data = request.get_json()
    if data:
        alert_log.append(data)
        stats['total']   += 1
        stats['attacks'] += 1
        print(f"[Dashboard] Alert received: "
              f"{data.get('attack_type')} from {data.get('src_ip')}")
    return jsonify({'status': 'ok'})


@app.route('/api/benign', methods=['POST'])
def receive_benign():
    """Receives benign flow counts from ids_engine.py"""
    stats['total']  += 1
    stats['benign'] += 1
    return jsonify({'status': 'ok'})


@app.route('/api/stats')
def get_stats():
    """Returns current stats as JSON"""
    return jsonify(stats)


@app.route('/api/alerts')
def get_alerts():
    """Returns last 50 alerts as JSON"""
    return jsonify(list(reversed(alert_log[-50:])))


@app.route('/api/predict', methods=['POST'])
def predict():
    """
    Optional: direct prediction endpoint
    Send raw features and get a classification back
    """
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 500

    data         = request.get_json()
    feature_dict = data.get('features', {})
    src_ip       = data.get('src_ip', 'unknown')

    vector = [feature_dict.get(col, 0) for col in feature_cols]
    X      = np.array(vector).reshape(1, -1)
    X      = imputer.transform(X)
    X      = scaler.transform(X)

    pred_idx   = model.predict(X)[0]
    pred_label = le.inverse_transform([pred_idx])[0]

    if hasattr(model, 'predict_proba'):
        proba      = model.predict_proba(X)[0]
        confidence = float(proba[pred_idx])
    else:
        confidence = 1.0

    is_attack = pred_label.lower() != 'benign'

    if is_attack:
        def sev(c):
            if c >= 0.90: return 'CRITICAL'
            if c >= 0.75: return 'HIGH'
            if c >= 0.60: return 'MEDIUM'
            return 'LOW'

        alert = {
            'timestamp':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip':      src_ip,
            'attack_type': pred_label,
            'confidence':  f"{confidence:.2%}",
            'severity':    sev(confidence)
        }
        alert_log.append(alert)
        stats['total']   += 1
        stats['attacks'] += 1
    else:
        stats['total']  += 1
        stats['benign'] += 1

    return jsonify({
        'label':      pred_label,
        'confidence': confidence,
        'is_attack':  is_attack
    })


# =============================================================
# Entry point
# =============================================================

if __name__ == '__main__':
    print("")
    print("=" * 50)
    print("  AI DDoS Detection Dashboard")
    print("=" * 50)
    print("  Local URL:   http://localhost:5000")
    print("  Network URL: http://<JETSON_IP>:5000")
    print("=" * 50)
    print("")
    app.run(host='0.0.0.0', port=5000, debug=False)
