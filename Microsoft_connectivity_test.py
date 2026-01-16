import json
import socket
import time
import ipaddress
import logging
import ssl
import threading
import requests
import random
import platform
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

# ---------------- CONFIG ----------------
SOURCE_URL = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
BASE_DIR = Path(__file__).parent
SOURCE_FILE = BASE_DIR / "microsoft-worldwide.json"
RESULT_FILE = BASE_DIR / "connection_results.json"
TIMEOUT = 3
MAX_WORKERS = 20
TLS_PORTS = {443}
MAX_RETRIES = 3
LOG_FILE = BASE_DIR / "connection_test.log"

EXPECTED_CA_KEYWORDS = (
    "Microsoft",
    "DigiCert",
    "GlobalSign"
)

FAILURE_HINTS = {
    "DNS": ("DNS resolution failure", "Check DNS forwarders, split DNS, or firewall DNS rules"),
    "TCP": ("Network connectivity blocked", "Verify firewall rules, routing, and proxy bypass"),
    "TLS": ("TLS handshake failure", "Verify TLS versions, cipher suites, and certificate trust"),
    "TLS_INSPECTION": ("TLS inspection detected", "Exclude Microsoft 365 endpoints from TLS inspection")
}
# ----------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

results = []
results_lock = threading.Lock()

# ---------- Helpers ----------

def download_source_json():
    logging.info("Downloading Microsoft endpoint JSON")
    r = requests.get(SOURCE_URL, timeout=10)
    r.raise_for_status()
    SOURCE_FILE.write_text(r.text, encoding="utf-8")

def load_json():
    return json.loads(SOURCE_FILE.read_text(encoding="utf-8"))

def parse_ports(port_string):
    return [int(p) for p in port_string.split(",") if p.strip().isdigit()]

def is_wildcard(host):
    return host.startswith("*.")

def resolve_dns_timed(host):
    start = time.perf_counter()
    try:
        socket.getaddrinfo(host, None)
        return True, round((time.perf_counter() - start) * 1000, 2)
    except Exception:
        return False, round((time.perf_counter() - start) * 1000, 2)

def first_ip_from_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return str(next(net.hosts()))
    except Exception:
        return None

# ---------- TLS Inspection Detection ----------

def detect_tls_inspection(cert, hostname):
    issuer = " ".join(x[0][1] for x in cert.get("issuer", []))
    subject = " ".join(x[0][1] for x in cert.get("subject", []))

    if not any(ca in issuer for ca in EXPECTED_CA_KEYWORDS):
        return True, "TLS_CERT_ISSUER_MISMATCH", f"Issuer: {issuer}"

    if hostname and hostname not in subject:
        return True, "TLS_HOSTNAME_MISMATCH", f"Subject: {subject}"

    return False, None, None

def extract_tls_details(sock):
    cert = sock.getpeercert()
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    expires = expires.replace(tzinfo=timezone.utc)

    return {
        "version": sock.version(),
        "cipher": sock.cipher()[0],
        "issuer": " ".join(x[0][1] for x in cert.get("issuer", [])),
        "expires_in_days": (expires - datetime.now(timezone.utc)).days
    }


# ---------- Connection Test ----------

def test_connection(service, target, port, is_dns, required):
    retry_outcome = "SUCCESS_FIRST_TRY"

    for attempt in range(1, MAX_RETRIES + 1):
        timings = {}
        start_total = time.perf_counter()
        success = False
        failure_type = None
        error = None
        error_code = None
        tls_details = None

        try:
            start_tcp = time.perf_counter()
            sock = socket.create_connection((target, port), timeout=TIMEOUT)
            timings["tcp_connect_ms"] = round((time.perf_counter() - start_tcp) * 1000, 2)

            if port in TLS_PORTS:
                start_tls = time.perf_counter()
                context = ssl.create_default_context()
                tls_sock = context.wrap_socket(sock, server_hostname=target if is_dns else None)
                timings["tls_handshake_ms"] = round((time.perf_counter() - start_tls) * 1000, 2)

                inspected, code, reason = detect_tls_inspection(tls_sock.getpeercert(), target if is_dns else None)
                if inspected:
                    failure_type = "TLS_INSPECTION"
                    error_code = code
                    error = reason
                    raise ssl.SSLError(reason)

                tls_details = extract_tls_details(tls_sock)
                tls_sock.close()
            else:
                sock.close()

            success = True

        except socket.gaierror as e:
            failure_type = "DNS"
            error_code = "DNS_RESOLUTION_FAILED"
            error = str(e)

        except ssl.SSLError as e:
            failure_type = failure_type or "TLS"
            error_code = error_code or "TLS_HANDSHAKE_FAILED"
            error = str(e)

        except Exception as e:
            failure_type = "TCP"
            error_code = "TCP_CONNECTION_FAILED"
            error = str(e)

        timings["total_ms"] = round((time.perf_counter() - start_total) * 1000, 2)

        if success:
            if attempt > 1:
                retry_outcome = "SUCCESS_AFTER_RETRY"
            break

        if attempt < MAX_RETRIES:
            retry_outcome = "FAILED_RETRYING"
            time.sleep((2 ** attempt) * random.uniform(0.1, 0.5))

    hint = FAILURE_HINTS.get(failure_type, (None, None))

    result = {
        "service": service,
        "target": target,
        "port": port,
        "required": required,
        "success": success,
        "failure_type": failure_type,
        "error_code": error_code,
        "error": error,
        "probable_cause": hint[0],
        "recommended_action": hint[1],
        "timings": timings,
        "tls_details": tls_details,
        "retries": attempt - 1,
        "retry_outcome": retry_outcome
    }

    with results_lock:
        results.append(result)

# ---------- Task Builder ----------

def build_tasks(data):
    tasks = []

    for entry in data:
        service = entry.get("serviceAreaDisplayName", "Unknown")
        tcp_ports = parse_ports(entry.get("tcpPorts", ""))
        required = entry.get("required", False)

        for url in entry.get("urls", []):
            if is_wildcard(url):
                continue
            dns_ok, _ = resolve_dns_timed(url)
            if not dns_ok:
                results.append({
                    "service": service,
                    "target": url,
                    "port": None,
                    "required": required,
                    "success": False,
                    "failure_type": "DNS",
                    "error_code": "DNS_RESOLUTION_FAILED",
                    "error": "DNS resolution failed",
                    "probable_cause": FAILURE_HINTS["DNS"][0],
                    "recommended_action": FAILURE_HINTS["DNS"][1]
                })
                continue
            for port in tcp_ports:
                tasks.append((service, url, port, True, required))

        for cidr in entry.get("ips", []):
            ip = first_ip_from_cidr(cidr)
            if ip:
                for port in tcp_ports:
                    tasks.append((service, ip, port, False, required))

    return tasks

# ---------- Summary ----------

def build_summary(results):
    summary = {
        "total_tests": len(results),
        "success": 0,
        "failed": 0,
        "failures_by_type": defaultdict(int),
        "average_time_ms": 0
    }

    service_stats = defaultdict(lambda: {"total": 0, "failed": 0})
    total_time = 0

    for r in results:
        service_stats[r["service"]]["total"] += 1
        if r["success"]:
            summary["success"] += 1
        else:
            summary["failed"] += 1
            service_stats[r["service"]]["failed"] += 1
            summary["failures_by_type"][r["failure_type"]] += 1
        total_time += r.get("timings", {}).get("total_ms", 0)

    for s, stats in service_stats.items():
        stats["health_score"] = round(100 - (stats["failed"] / stats["total"] * 100), 2)

    if results:
        summary["average_time_ms"] = round(total_time / len(results), 2)

    return summary, service_stats

# ---------- Main ----------

def main():
    download_source_json()
    data = load_json()
    tasks = build_tasks(data)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(test_connection, *task)
            for task in tasks
        ]
        for _ in as_completed(futures):
            pass

    summary, services = build_summary(results)

    output = {
        "environment": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "summary": summary,
        "services": services,
        "results": results
    }

    RESULT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")

    exit_code = determine_exit_code(summary)

    logging.info("All endpoints processed")
    logging.info(f"Final status: success={summary['success']} failed={summary['failed']}")
    logging.info(f"Exit code: {exit_code}")

    return exit_code

def determine_exit_code(summary):
    if summary["failures_by_type"].get("DNS"):
        return 10
    if summary["failures_by_type"].get("TLS_INSPECTION"):
        return 20
    if summary["failed"]:
        return 1
    return 0
   
if __name__ == "__main__":
    code = main()
    sys.exit(code)

