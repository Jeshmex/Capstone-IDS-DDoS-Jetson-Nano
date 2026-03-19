================================================================
  AI-Based DDoS Intrusion Detection System
  Jetson Orin Nano Deployment Guide
  Jeshua Vargas Valenzuela - CSC 520 - Fall 2025
================================================================

FILES IN THIS PACKAGE
---------------------
  ids_engine.py         Core IDS - captures packets, runs ML
  app.py                Flask web dashboard
  test_ids.py           System verification script
  install.sh            Automated setup script
  README.txt            This file

  You must also copy these from your Jupyter project folder:
  best_model.pkl        Trained ML model
  scaler.pkl            Feature scaler
  imputer.pkl           NaN imputer
  label_encoder.pkl     Label decoder
  feature_columns.pkl   Feature column order


================================================================
STEP 1 - PREPARE YOUR WINDOWS MACHINE
================================================================

1a. Open Jupyter and run this to confirm all pkl files exist:

    import os
    files = ['best_model.pkl','scaler.pkl','imputer.pkl',
             'label_encoder.pkl','feature_columns.pkl']
    for f in files:
        path = os.path.join(r'C:\Users\jeshb\Desktop\Capstone Project', f)
        size = os.path.getsize(path)/1024 if os.path.exists(path) else 0
        print(f"{'OK' if os.path.exists(path) else 'MISSING':8} {f}  {size:.0f} KB")

1b. All 5 pkl files must show OK before continuing.


================================================================
STEP 2 - CONNECT TO JETSON
================================================================

2a. Connect Jetson to your network (ethernet recommended).

2b. Find the Jetson IP address.
    On the Jetson (with monitor/keyboard attached):
      hostname -I

    Or check your router admin page for connected devices.

2c. Open Windows PowerShell and test SSH:
      ssh jetson@<JETSON_IP>

    Default password: jetson
    (or whatever you set during Jetson setup)

2d. Once SSH works, keep this terminal open.
    You will use it for all commands on the Jetson.


================================================================
STEP 3 - CREATE FOLDER ON JETSON
================================================================

Run these commands in your SSH terminal (on the Jetson):

    mkdir -p /home/jetson/ids
    echo "Folder created"


================================================================
STEP 4 - TRANSFER FILES FROM WINDOWS TO JETSON
================================================================

Open a NEW Windows PowerShell window (not SSH).
Navigate to your project folder and run:

    cd "C:\Users\jeshb\Desktop\Capstone Project"

    scp ids_engine.py app.py test_ids.py install.sh jetson@<JETSON_IP>:/home/jetson/ids/

    scp best_model.pkl scaler.pkl imputer.pkl label_encoder.pkl feature_columns.pkl jetson@<JETSON_IP>:/home/jetson/ids/

Replace <JETSON_IP> with your actual Jetson IP address.
You will be prompted for the password each time.

Verify the transfer on Jetson (SSH terminal):

    ls -lh /home/jetson/ids/

You should see all 9 files listed with their sizes.


================================================================
STEP 5 - RUN THE INSTALL SCRIPT ON JETSON
================================================================

In your SSH terminal (on Jetson):

    cd /home/jetson/ids
    chmod +x install.sh
    sudo ./install.sh

This script will:
  - Install all Python packages (flask, scikit-learn, scapy, etc.)
  - Detect your network interface name automatically
  - Update ids_engine.py with the correct interface
  - Create systemd services for auto-start on boot
  - Print your dashboard URL when done

Wait for it to finish. It takes about 2-5 minutes.


================================================================
STEP 6 - VERIFY SETUP
================================================================

Run the test script on Jetson:

    cd /home/jetson/ids
    python3 test_ids.py

All checks should pass except:
  - Check 7 (root permission) - expected to warn
  - Check 8 (dashboard) - expected to fail until app.py is started

If any other check fails, follow the error message to fix it.


================================================================
STEP 7 - CONFIGURE SWITCH SPAN PORT
================================================================

The Jetson must receive mirrored traffic from your switch.

SPAN port = a switch feature that copies all traffic from
one port to another port. The Jetson listens on the copy.

For a managed switch (Cisco example):
    Switch(config)# monitor session 1 source interface Gi0/1
    Switch(config)# monitor session 1 destination interface Gi0/2
    Where Gi0/2 is the port the Jetson is plugged into.

For a web-managed switch (Netgear, TP-Link, etc.):
    Log into switch web interface
    Go to: Switching > Port Mirroring
    Source port:      port you want to monitor
    Destination port: port Jetson is connected to
    Click Apply/Save

Verify SPAN is working on Jetson:
    sudo python3 -c "
from scapy.all import sniff, IP
print('Listening 10 seconds...')
pkts = sniff(iface='eth0', filter='ip', timeout=10)
print(f'Captured {len(pkts)} packets')
for p in pkts[:3]:
    if IP in p: print(f'  {p[IP].src} -> {p[IP].dst}')
"

If you see packets from other devices, SPAN is working.
If you only see packets addressed to the Jetson, SPAN is
not configured yet.


================================================================
STEP 8 - START THE IDS
================================================================

You need TWO terminal windows on the Jetson.
Open a second SSH session from Windows PowerShell:
    ssh jetson@<JETSON_IP>

Terminal 1 - Start the dashboard:
    cd /home/jetson/ids
    python3 app.py

    You should see:
      [Dashboard] Models loaded: X classes
      Dashboard running at http://localhost:5000

Terminal 2 - Start the IDS engine:
    cd /home/jetson/ids
    sudo python3 ids_engine.py

    You should see:
      [IDS] Model type: RandomForestClassifier
      [IDS] Interface:  eth0
      [IDS] Starting capture on interface: eth0


================================================================
STEP 9 - OPEN THE DASHBOARD
================================================================

On any device connected to the same network,
open a web browser and go to:

    http://<JETSON_IP>:5000

You should see the dashboard with:
  - Total Flows counter
  - Attacks Detected counter
  - Benign Flows counter
  - Attack Rate percentage
  - Recent Alerts table (empty until attacks are detected)

The page auto-refreshes every 5 seconds.


================================================================
STEP 10 - AUTO-START ON BOOT (OPTIONAL)
================================================================

If the install script completed successfully, the services
are already enabled. To start them now without rebooting:

    sudo systemctl start ids-dashboard
    sudo systemctl start ids-engine

Check they are running:
    sudo systemctl status ids-dashboard
    sudo systemctl status ids-engine

View live logs:
    sudo journalctl -u ids-engine -f
    sudo journalctl -u ids-dashboard -f
    (Press Ctrl+C to stop watching)

Now every time Jetson powers on, the IDS starts automatically.


================================================================
TROUBLESHOOTING
================================================================

PROBLEM: scp transfer fails
FIX:     Check the IP address is correct
         Make sure SSH is enabled on Jetson (default: yes)
         Try: ping <JETSON_IP> to confirm network connection

PROBLEM: install.sh fails on pip install
FIX:     Run: sudo apt install python3-pip
         Then: pip3 install flask scikit-learn numpy scapy joblib requests

PROBLEM: "No module named X" error
FIX:     Run: pip3 install X
         Replace X with the missing module name

PROBLEM: Dashboard at http://JETSON_IP:5000 not loading
FIX:     Check app.py is running: ps aux | grep app.py
         Open firewall port: sudo ufw allow 5000
         Confirm Jetson IP: hostname -I

PROBLEM: No packets captured by ids_engine.py
FIX:     Check interface name: ip link show
         Edit INTERFACE in ids_engine.py to match
         Confirm SPAN port is configured on switch
         Make sure running with sudo

PROBLEM: "Permission denied" when running ids_engine.py
FIX:     Always run with sudo: sudo python3 ids_engine.py
         Raw packet capture requires root privileges

PROBLEM: Wrong interface name
FIX:     Run: ip link show
         Find your ethernet interface (eth0, enp3s0, etc.)
         Edit ids_engine.py line:
           INTERFACE = 'eth0'   <-- change to your interface
         Restart: sudo systemctl restart ids-engine

PROBLEM: Model loads but predictions all say Benign
FIX:     This may mean your dataset only had Benign labels
         during training. Check label distribution in Jupyter:
           import joblib
           le = joblib.load('label_encoder.pkl')
           print(le.classes_)
         If only ['Benign'] appears, retrain with full dataset


================================================================
SYSTEM ARCHITECTURE SUMMARY
================================================================

Network Switch (SPAN source port monitors production traffic)
       |
       | copy of all traffic
       |
Jetson Orin Nano (eth0 connected to SPAN destination port)
       |
  ids_engine.py
       |-- Scapy captures every IP packet
       |-- FlowTracker groups packets by src/dst/port/proto
       |-- After 10 packets: extract 64 flow features
       |-- Scale features with saved StandardScaler
       |-- Run through trained ML model (Random Forest etc.)
       |-- Attack detected? --> POST alert to app.py
       |-- Benign? --> increment counter only
       |
  app.py (Flask)
       |-- Receives alerts from ids_engine.py
       |-- Serves web dashboard on port 5000
       |-- Auto-refreshes every 5 seconds
       |
  Admin Browser (any device on network)
       --> http://JETSON_IP:5000


================================================================
END OF DEPLOYMENT GUIDE
================================================================
