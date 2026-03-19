# =============================================================
# ids_engine.py
# AI-Based DDoS Intrusion Detection System - Capture Engine
# Jeshua Vargas Valenzuela - CSC 520
#
# Run on Jetson Orin Nano:
#   sudo python3 ids_engine.py
#
# Requires app.py to be running first in a separate terminal:
#   python3 app.py
# =============================================================

import os
import time
import joblib
import numpy as np
import requests
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict


# =============================================================
# CONFIGURATION - Edit these values for your setup
# =============================================================

INTERFACE     = 'eth0'               # network interface name
                                     # run: ip link show
                                     # to find your interface

DASHBOARD_URL = 'http://localhost:5000'  # Flask dashboard URL

MIN_PACKETS   = 10                   # packets before classifying
FLOW_TIMEOUT  = 60                   # seconds before flow expires


# =============================================================
# Flow Tracker - groups packets into flows
# =============================================================

class FlowTracker:

    def __init__(self):
        self.flows       = defaultdict(lambda: {
            'packets':    [],
            'start_time': None,
            'src_ip':     None,
            'dst_ip':     None,
        })
        self.feat_cols = joblib.load(
            os.path.join(os.path.dirname(
                os.path.abspath(__file__)), 'feature_columns.pkl'))

    def get_flow_key(self, packet):
        if IP not in packet:
            return None, None
        src   = packet[IP].src
        dst   = packet[IP].dst
        proto = packet[IP].proto
        sport = packet[TCP].sport if TCP in packet else (
                packet[UDP].sport if UDP in packet else 0)
        dport = packet[TCP].dport if TCP in packet else (
                packet[UDP].dport if UDP in packet else 0)
        key   = f"{src}:{sport}-{dst}:{dport}-{proto}"
        return key, src

    def add_packet(self, packet):
        key, src_ip = self.get_flow_key(packet)
        if key is None:
            return None, None

        flow = self.flows[key]
        if flow['start_time'] is None:
            flow['start_time'] = time.time()
            flow['src_ip']     = packet[IP].src
            flow['dst_ip']     = packet[IP].dst

        flow['packets'].append({
            'time':   time.time(),
            'length': len(packet),
            'packet': packet
        })

        if len(flow['packets']) >= MIN_PACKETS:
            features = self.extract_features(flow)
            src      = flow['src_ip']
            del self.flows[key]
            return features, src

        return None, None

    def extract_features(self, flow):
        pkts    = flow['packets']
        lengths = [p['length'] for p in pkts]
        times   = [p['time']   for p in pkts]
        dur     = (times[-1] - times[0]) * 1e6

        iats    = [(times[i+1] - times[i]) * 1e6
                   for i in range(len(times) - 1)]

        features = {
            'Dst Port':          self._get_dport(pkts[0]['packet']),
            'Protocol':          self._get_proto(pkts[0]['packet']),
            'Flow Duration':     dur,
            'Tot Fwd Pkts':      len(pkts),
            'Tot Bwd Pkts':      0,
            'TotLen Fwd Pkts':   sum(lengths),
            'TotLen Bwd Pkts':   0,
            'Fwd Pkt Len Max':   max(lengths),
            'Fwd Pkt Len Min':   min(lengths),
            'Fwd Pkt Len Mean':  float(np.mean(lengths)),
            'Fwd Pkt Len Std':   float(np.std(lengths)),
            'Bwd Pkt Len Max':   0,
            'Bwd Pkt Len Min':   0,
            'Bwd Pkt Len Mean':  0,
            'Bwd Pkt Len Std':   0,
            'Flow Byts/s':       sum(lengths) / (dur / 1e6) if dur > 0 else 0,
            'Flow Pkts/s':       len(pkts)    / (dur / 1e6) if dur > 0 else 0,
            'Flow IAT Mean':     float(np.mean(iats)) if iats else 0,
            'Flow IAT Std':      float(np.std(iats))  if iats else 0,
            'Flow IAT Max':      float(max(iats))      if iats else 0,
            'Flow IAT Min':      float(min(iats))      if iats else 0,
            'Fwd IAT Tot':       sum(iats),
            'Fwd IAT Mean':      float(np.mean(iats)) if iats else 0,
            'Fwd IAT Std':       float(np.std(iats))  if iats else 0,
            'Fwd IAT Max':       float(max(iats))      if iats else 0,
            'Fwd IAT Min':       float(min(iats))      if iats else 0,
            'Bwd IAT Tot':       0,
            'Bwd IAT Mean':      0,
            'Bwd IAT Std':       0,
            'Bwd IAT Max':       0,
            'Bwd IAT Min':       0,
            'Fwd PSH Flags':     self._count_flag(pkts, 'P'),
            'Fwd Header Len':    len(pkts) * 20,
            'Bwd Header Len':    0,
            'Fwd Pkts/s':        len(pkts) / (dur / 1e6) if dur > 0 else 0,
            'Bwd Pkts/s':        0,
            'Pkt Len Min':       min(lengths),
            'Pkt Len Max':       max(lengths),
            'Pkt Len Mean':      float(np.mean(lengths)),
            'Pkt Len Std':       float(np.std(lengths)),
            'Pkt Len Var':       float(np.var(lengths)),
            'FIN Flag Cnt':      self._count_flag(pkts, 'F'),
            'SYN Flag Cnt':      self._count_flag(pkts, 'S'),
            'RST Flag Cnt':      self._count_flag(pkts, 'R'),
            'PSH Flag Cnt':      self._count_flag(pkts, 'P'),
            'ACK Flag Cnt':      self._count_flag(pkts, 'A'),
            'URG Flag Cnt':      self._count_flag(pkts, 'U'),
            'ECE Flag Cnt':      self._count_flag(pkts, 'E'),
            'Down/Up Ratio':     0,
            'Pkt Size Avg':      float(np.mean(lengths)),
            'Fwd Seg Size Avg':  float(np.mean(lengths)),
            'Bwd Seg Size Avg':  0,
            'Fwd Act Data Pkts': len(pkts),
            'Fwd Seg Size Min':  min(lengths),
            'Init Fwd Win Byts': self._get_win(pkts[0]['packet']),
            'Init Bwd Win Byts': -1,
            'Active Mean':       0,
            'Active Std':        0,
            'Active Max':        0,
            'Active Min':        0,
            'Idle Mean':         0,
            'Idle Std':          0,
            'Idle Max':          0,
            'Idle Min':          0,
        }

        # Fill any remaining columns with 0
        for col in self.feat_cols:
            if col not in features:
                features[col] = 0

        return features

    def _get_dport(self, pkt):
        if TCP in pkt: return pkt[TCP].dport
        if UDP in pkt: return pkt[UDP].dport
        return 0

    def _get_proto(self, pkt):
        if IP in pkt: return pkt[IP].proto
        return 0

    def _get_win(self, pkt):
        if TCP in pkt: return pkt[TCP].window
        return -1

    def _count_flag(self, pkts, flag):
        count = 0
        for p in pkts:
            if TCP in p['packet']:
                if flag in str(p['packet'][TCP].flags):
                    count += 1
        return count

    def cleanup_old_flows(self):
        now     = time.time()
        expired = [
            k for k, v in self.flows.items()
            if v['start_time'] and
               now - v['start_time'] > FLOW_TIMEOUT
        ]
        for k in expired:
            del self.flows[k]
        if expired:
            print(f"[CLEANUP] Removed {len(expired)} timed-out flows")


# =============================================================
# Jetson IDS - main class
# =============================================================

class JetsonIDS:

    def __init__(self):
        print("")
        print("=" * 50)
        print("  AI DDoS IDS Engine - Jetson Orin Nano")
        print("=" * 50)

        base = os.path.dirname(os.path.abspath(__file__))

        print("[IDS] Loading ML model...")
        self.model        = joblib.load(os.path.join(base, 'best_model.pkl'))
        self.scaler       = joblib.load(os.path.join(base, 'scaler.pkl'))
        self.imputer      = joblib.load(os.path.join(base, 'imputer.pkl'))
        self.le           = joblib.load(os.path.join(base, 'label_encoder.pkl'))
        self.feature_cols = joblib.load(os.path.join(base, 'feature_columns.pkl'))

        self.tracker = FlowTracker()
        self.stats   = {
            'packets_seen': 0,
            'flows_total':  0,
            'attacks':      0,
            'benign':       0,
            'start_time':   datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        print(f"[IDS] Model type:      {type(self.model).__name__}")
        print(f"[IDS] Classes ({len(self.le.classes_)}):    "
              f"{self.le.classes_.tolist()}")
        print(f"[IDS] Features:        {len(self.feature_cols)}")
        print(f"[IDS] Interface:       {INTERFACE}")
        print(f"[IDS] Dashboard:       {DASHBOARD_URL}")
        print(f"[IDS] Min packets:     {MIN_PACKETS}")
        print(f"[IDS] Flow timeout:    {FLOW_TIMEOUT}s")
        print("=" * 50)
        print("")

    def packet_callback(self, packet):
        self.stats['packets_seen'] += 1

        features, src_ip = self.tracker.add_packet(packet)

        if features is None:
            return

        # Build feature vector
        vector = [features.get(col, 0) for col in self.feature_cols]
        X      = np.array(vector).reshape(1, -1)
        X      = self.imputer.transform(X)
        X      = self.scaler.transform(X)

        # Predict
        pred_idx   = self.model.predict(X)[0]
        pred_label = self.le.inverse_transform([pred_idx])[0]

        if hasattr(self.model, 'predict_proba'):
            proba      = self.model.predict_proba(X)[0]
            confidence = float(proba[pred_idx])
        else:
            confidence = 1.0

        self.stats['flows_total'] += 1

        if pred_label.lower() != 'benign':
            self.stats['attacks'] += 1
            self._send_alert(src_ip, pred_label, confidence)
        else:
            self.stats['benign'] += 1

        # Print stats every 100 flows
        if self.stats['flows_total'] % 100 == 0:
            self._print_stats()

        # Cleanup old flows every 500 packets
        if self.stats['packets_seen'] % 500 == 0:
            self.tracker.cleanup_old_flows()

    def _send_alert(self, src_ip, label, confidence):
        severity  = self._severity(confidence)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Print to console
        print(f"[ALERT] {timestamp} | "
              f"{label:25s} | "
              f"Conf: {confidence:.2%} | "
              f"Sev: {severity:8s} | "
              f"Src: {src_ip}")

        # Send to Flask dashboard
        try:
            requests.post(
                f"{DASHBOARD_URL}/api/alert",
                json={
                    'timestamp':   timestamp,
                    'src_ip':      src_ip,
                    'attack_type': label,
                    'confidence':  f"{confidence:.2%}",
                    'severity':    severity
                },
                timeout=0.5
            )
        except Exception:
            # Dashboard offline - IDS keeps running regardless
            pass

    def _severity(self, confidence):
        if confidence >= 0.90: return 'CRITICAL'
        if confidence >= 0.75: return 'HIGH'
        if confidence >= 0.60: return 'MEDIUM'
        return 'LOW'

    def _print_stats(self):
        total     = self.stats['flows_total']
        attack_rt = (self.stats['attacks'] / total * 100
                     if total > 0 else 0)
        print(f"[STATS] Packets: {self.stats['packets_seen']:6,} | "
              f"Flows: {total:6,} | "
              f"Attacks: {self.stats['attacks']:5,} | "
              f"Attack Rate: {attack_rt:.1f}%")

    def start(self):
        print(f"[IDS] Starting capture on interface: {INTERFACE}")
        print(f"[IDS] Open dashboard at: {DASHBOARD_URL}")
        print(f"[IDS] Press Ctrl+C to stop")
        print("")

        try:
            sniff(
                iface  = INTERFACE,
                prn    = self.packet_callback,
                store  = False,
                filter = 'ip'
            )
        except KeyboardInterrupt:
            print("\n[IDS] Stopped by user")
            self._print_stats()
        except PermissionError:
            print("\n[ERROR] Permission denied.")
            print("        Run with sudo:  sudo python3 ids_engine.py")
        except Exception as e:
            print(f"\n[ERROR] {e}")
            print(f"        Check interface name with: ip link show")
            print(f"        Current interface set to:  {INTERFACE}")


# =============================================================
# Entry point
# =============================================================

if __name__ == '__main__':
    ids = JetsonIDS()
    ids.start()
