from flask import Flask, render_template, jsonify
import logging

app = Flask(__name__)

# Disable Flask's default logging to prevent unwanted prints in the terminal
app.logger.setLevel(logging.ERROR)

ALERT_FILE = "logs/alerts.log"

def parse_alerts():
    dos_attacks_signature = {}
    dos_attacks_anomaly = {}
    port_scans_signature = {}
    port_scans_anomaly = {}

    try:
        with open(ALERT_FILE, "r") as file:
            for line in file:
                # Signature-based DoS
                if "[SIGNATURE ALERT - DoS]" in line:
                    ip = line.split("from ")[1].strip()
                    dos_attacks_signature[ip] = dos_attacks_signature.get(ip, 0) + 1

                # Anomaly-based DoS
                elif "[ANOMALY ALERT - DoS]" in line:
                    ip = line.split("IP: ")[1].split()[0]
                    dos_attacks_anomaly[ip] = dos_attacks_anomaly.get(ip, 0) + 1

                # Signature-based Port Scan
                elif "[SIGNATURE ALERT - Port Scan]" in line:
                    ip = line.split("from ")[1].split()[0]
                    port_scans_signature[ip] = port_scans_signature.get(ip, 0) + 1

                # Anomaly-based Port Scan
                elif "Port Scan Detected! IP:" in line:
                    ip = line.split("IP: ")[1].split()[0]
                    port_scans_anomaly[ip] = port_scans_anomaly.get(ip, 0) + 1

    except FileNotFoundError:
        pass

    return dos_attacks_signature, dos_attacks_anomaly, port_scans_signature, port_scans_anomaly

    dos_attacks_signature = {}
    dos_attacks_anomaly = {}
    port_scans_signature = {}
    port_scans_anomaly = {}

    try:
        with open(ALERT_FILE, "r") as file:
            for line in file:
                # Signature-based DoS
                if "DoS Attack Detected (Signature)" in line:
                    ip = line.split("IP: ")[1].split()[0]
                    dos_attacks_signature[ip] = dos_attacks_signature.get(ip, 0) + 1

                # Anomaly-based DoS
                elif "DoS Attack Detected (Anomaly)" in line:
                    ip = line.split("IP: ")[1].split()[0]
                    dos_attacks_anomaly[ip] = dos_attacks_anomaly.get(ip, 0) + 1

                # Signature-based Port Scan
                elif "Port Scan Detected (Signature)" in line:
                    ip = line.split("IP: ")[1].split()[0]
                    port_scans_signature[ip] = port_scans_signature.get(ip, 0) + 1

                # Anomaly-based Port Scan
                elif "Port Scan Detected (Anomaly)" in line:
                    ip = line.split("IP: ")[1].split()[0]
                    port_scans_anomaly[ip] = port_scans_anomaly.get(ip, 0) + 1

    except FileNotFoundError:
        pass

    # Return empty dictionaries if no alerts found
    return dos_attacks_signature, dos_attacks_anomaly, port_scans_signature, port_scans_anomaly

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def get_data():
    # Parse alerts and return empty lists if no data exists
    dos_sig, dos_anom, port_sig, port_anom = parse_alerts()

    # If no attacks, return empty lists instead of None
    return jsonify({
        "dos_signature": [{"ip": ip, "count": count} for ip, count in dos_sig.items()] if dos_sig else [],
        "dos_anomaly": [{"ip": ip, "count": count} for ip, count in dos_anom.items()] if dos_anom else [],
        "port_signature": [{"ip": ip, "count": count} for ip, count in port_sig.items()] if port_sig else [],
        "port_anomaly": [{"ip": ip, "count": count} for ip, count in port_anom.items()] if port_anom else []
    })

if __name__ == "__main__":
    # Running the app without debug mode, so no unnecessary prints will show
    app.run(debug=False)