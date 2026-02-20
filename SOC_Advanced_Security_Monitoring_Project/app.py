
from flask import Flask, render_template, request
import datetime

app = Flask(__name__)

alerts = []

def detect_bruteforce(logs):
    failed_attempts = {}
    for log in logs:
        if "FAILED" in log:
            ip = log.split("IP: ")[1]
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    for ip, count in failed_attempts.items():
        if count >= 5:
            alerts.append({
                "type": "Brute Force Attack",
                "ip": ip,
                "severity": "High",
                "time": str(datetime.datetime.now())
            })

@app.route("/")
def home():
    return render_template("dashboard.html", alerts=alerts)

@app.route("/analyze", methods=["POST"])
def analyze():
    log_data = request.form["logs"]
    logs = log_data.strip().split("\n")
    detect_bruteforce(logs)
    return render_template("dashboard.html", alerts=alerts)

@app.route("/clear")
def clear():
    alerts.clear()
    return render_template("dashboard.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)
