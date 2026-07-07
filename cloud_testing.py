#!/usr/bin/env python3
"""
cloud_monitor.py
Unified monitoring script for Local, AWS, Azure and GCP hosts.

Features
--------
- Auto-detects the environment the script is running on (Local / AWS / Azure / GCP)
  using cloud provider metadata endpoints.
- Collects CPU, Memory, Disk and Network metrics via psutil.
- Sends alerts through Email, Slack and/or Microsoft Teams when thresholds are breached.
- Rotating file + console logging.

Install:
    pip install psutil requests boto3 azure-identity azure-mgmt-compute google-cloud-compute

Configuration:
    All secrets/config are read from environment variables (see CONFIG section below)
    so nothing sensitive needs to be hardcoded or committed to source control.

    Required for email alerts:
        SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO
    Required for Slack alerts:
        SLACK_WEBHOOK_URL
    Required for Teams alerts:
        TEAMS_WEBHOOK_URL
"""

import os
import time
import socket
import logging
import smtplib
import argparse
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None


# --------------------------------------------------------------------------- #
# CONFIG
# --------------------------------------------------------------------------- #

CPU_THRESHOLD = float(os.getenv("CPU_THRESHOLD", 1))
RAM_THRESHOLD = float(os.getenv("RAM_THRESHOLD", 1))
DISK_THRESHOLD = float(os.getenv("DISK_THRESHOLD", 1))
NET_ERROR_THRESHOLD = int(os.getenv("NET_ERROR_THRESHOLD", 1))  # cumulative errin+errout

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 10))  # seconds
METADATA_TIMEOUT = float(os.getenv("METADATA_TIMEOUT", 1.5))  # seconds

# Email
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "Enter email ID from which you wish to send emails")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "Enter Gmail App Password refer this to generate it : https://youtu.be/ECi_9BiBUug ")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "gmailid1,gmailid2,gmailid3")

# Slack / Teams
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")

LOG_FILE = os.getenv("LOG_FILE", "cloud_monitor.log")


# --------------------------------------------------------------------------- #
# LOGGING
# --------------------------------------------------------------------------- #

logger = logging.getLogger("cloud_monitor")
logger.setLevel(logging.INFO)

_formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

_file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
_file_handler.setFormatter(_formatter)
logger.addHandler(_file_handler)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_formatter)
logger.addHandler(_console_handler)


# --------------------------------------------------------------------------- #
# ENVIRONMENT AUTO-DETECTION
# --------------------------------------------------------------------------- #

def _metadata_reachable(url, headers=None):
    if requests is None:
        return False
    try:
        r = requests.get(url, headers=headers or {}, timeout=METADATA_TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


def detect_environment():
    """Return one of: 'aws', 'azure', 'gcp', 'local'."""
    # AWS IMDSv2 first (token-based), fall back to IMDSv1-style GET.
    if requests is not None:
        try:
            token_resp = requests.put(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=METADATA_TIMEOUT,
            )
            if token_resp.status_code == 200:
                token = token_resp.text
                r = requests.get(
                    "http://169.254.169.254/latest/meta-data/instance-id",
                    headers={"X-aws-ec2-metadata-token": token},
                    timeout=METADATA_TIMEOUT,
                )
                if r.status_code == 200:
                    return "aws"
        except Exception:
            pass

    if _metadata_reachable(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata": "true"},
    ):
        return "azure"

    if _metadata_reachable(
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        headers={"Metadata-Flavor": "Google"},
    ):
        return "gcp"

    return "local"


# --------------------------------------------------------------------------- #
# METRIC COLLECTION
# --------------------------------------------------------------------------- #

_last_net_counters = {"time": None, "sent": 0, "recv": 0}


def collect_metrics():
    """Collect CPU / RAM / Disk / Network metrics. Returns a dict."""
    if psutil is None:
        logger.error("psutil is not installed; cannot collect system metrics.")
        return {}

    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()

    now = time.time()
    sent_rate = recv_rate = 0.0
    if _last_net_counters["time"] is not None:
        elapsed = max(now - _last_net_counters["time"], 1e-6)
        sent_rate = (net.bytes_sent - _last_net_counters["sent"]) / elapsed / 1024  # KB/s
        recv_rate = (net.bytes_recv - _last_net_counters["recv"]) / elapsed / 1024  # KB/s
    _last_net_counters.update(time=now, sent=net.bytes_sent, recv=net.bytes_recv)

    metrics = {
        "hostname": socket.gethostname(),
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "disk_percent": disk.percent,
        "net_sent_kbps": round(sent_rate, 2),
        "net_recv_kbps": round(recv_rate, 2),
        "net_errin": net.errin,
        "net_errout": net.errout,
    }
    return metrics


def evaluate_alerts(metrics):
    """Return a list of human-readable alert strings for any breached threshold."""
    alerts = []
    if not metrics:
        return alerts

    if metrics["cpu_percent"] > CPU_THRESHOLD:
        alerts.append(f"CPU high: {metrics['cpu_percent']}% (threshold {CPU_THRESHOLD}%)")
    if metrics["ram_percent"] > RAM_THRESHOLD:
        alerts.append(f"RAM high: {metrics['ram_percent']}% (threshold {RAM_THRESHOLD}%)")
    if metrics["disk_percent"] > DISK_THRESHOLD:
        alerts.append(f"Disk high: {metrics['disk_percent']}% (threshold {DISK_THRESHOLD}%)")
    net_errors = metrics["net_errin"] + metrics["net_errout"]
    if net_errors > NET_ERROR_THRESHOLD:
        alerts.append(f"Network errors high: {net_errors} (threshold {NET_ERROR_THRESHOLD})")
    return alerts


# --------------------------------------------------------------------------- #
# CLOUD-SPECIFIC EXTRAS (best-effort, non-fatal if SDK/credentials are missing)
# --------------------------------------------------------------------------- #

def extra_aws_info():
    try:
        import boto3
        ec2 = boto3.client("ec2")
        res = ec2.describe_instances()
        count = sum(len(r["Instances"]) for r in res["Reservations"])
        return f"AWS EC2 instances visible to these credentials: {count}"
    except Exception as e:
        logger.warning(f"AWS extra info unavailable: {e}")
        return None


def extra_azure_info():
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
        return "Azure detected. Configure azure-mgmt-compute calls here for VM-level detail."
    except Exception as e:
        logger.warning(f"Azure extra info unavailable: {e}")
        return None


def extra_gcp_info():
    try:
        from google.cloud import compute_v1  # noqa: F401
        return "GCP detected. Configure google-cloud-compute calls here for instance-level detail."
    except Exception as e:
        logger.warning(f"GCP extra info unavailable: {e}")
        return None


# --------------------------------------------------------------------------- #
# ALERTING
# --------------------------------------------------------------------------- #

def send_email(subject, body):
    if not (SMTP_SERVER and SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL_TO):
        logger.debug("Email not configured; skipping email alert.")
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL_TO
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
        logger.info("Email alert sent.")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")


def send_slack(subject, body):
    if not SLACK_WEBHOOK_URL:
        logger.debug("Slack not configured; skipping Slack alert.")
        return
    if requests is None:
        logger.error("requests library not installed; cannot send Slack alert.")
        return
    try:
        payload = {"text": f"*{subject}*\n{body}"}
        r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
        logger.info("Slack alert sent.")
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")


def send_teams(subject, body):
    if not TEAMS_WEBHOOK_URL:
        logger.debug("Teams not configured; skipping Teams alert.")
        return
    if requests is None:
        logger.error("requests library not installed; cannot send Teams alert.")
        return
    try:
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": subject,
            "themeColor": "FF0000",
            "title": subject,
            "text": body.replace("\n", "\n\n"),
        }
        r = requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
        logger.info("Teams alert sent.")
    except Exception as e:
        logger.error(f"Failed to send Teams alert: {e}")


def dispatch_alerts(env, metrics, alerts):
    if not alerts:
        return
    subject = f"[{env.upper()}] Resource Alert on {metrics.get('hostname', 'unknown host')}"
    body = "\n".join(alerts)
    logger.warning(f"Threshold breach detected: {body}")
    send_email(subject, body)
    send_slack(subject, body)
    send_teams(subject, body)


# --------------------------------------------------------------------------- #
# MAIN LOOP
# --------------------------------------------------------------------------- #

def run_once(env):
    metrics = collect_metrics()
    if metrics:
        logger.info(
            f"[{env.upper()}] host={metrics['hostname']} "
            f"CPU={metrics['cpu_percent']}% RAM={metrics['ram_percent']}% "
            f"DISK={metrics['disk_percent']}% "
            f"NET_SENT={metrics['net_sent_kbps']}KB/s NET_RECV={metrics['net_recv_kbps']}KB/s "
            f"NET_ERR={metrics['net_errin'] + metrics['net_errout']}"
        )
    alerts = evaluate_alerts(metrics)
    dispatch_alerts(env, metrics, alerts)

    extra_info = {"aws": extra_aws_info, "azure": extra_azure_info, "gcp": extra_gcp_info}.get(env)
    if extra_info:
        info = extra_info()
        if info:
            logger.info(info)


def main():
    parser = argparse.ArgumentParser(description="Unified Local/AWS/Azure/GCP resource monitor.")
    parser.add_argument("--once", action="store_true", help="Run a single check and exit (no loop).")
    parser.add_argument(
        "--interval", type=int, default=CHECK_INTERVAL, help="Seconds between checks (default: %(default)s)."
    )
    args = parser.parse_args()

    if psutil is None:
        logger.error("psutil is required. Install it with: pip install psutil")
        return

    env = detect_environment()
    logger.info(f"Detected environment: {env.upper()}")

    if args.once:
        run_once(env)
        return

    while True:
        try:
            run_once(env)
        except Exception as e:
            logger.error(f"Unhandled error during monitoring cycle: {e}")
        logger.info(f"Sleeping {args.interval} seconds...")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
