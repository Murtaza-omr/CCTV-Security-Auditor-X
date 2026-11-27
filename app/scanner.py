import ipaddress
import socket
import ssl
import re
import json
import time
import uuid
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import psutil
import requests

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

PORTS = {
    80: "HTTP", 443: "HTTPS", 554: "RTSP",
    8000: "HTTP alternate", 8080: "HTTP alternate",
    8081: "HTTP alternate", 8443: "HTTPS alternate",
    8899: "ONVIF candidate", 37777: "DVR service candidate",
    34567: "DVR service candidate", 5000: "Web service"
}
USER_AGENT = "CCTV-Security-Auditor-X/1.0 (authorized defensive assessment)"

def adapters():
    output = []
    for name, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        ipv4 = []
        for a in addrs:
            if a.family == socket.AF_INET:
                ipv4.append({"address": a.address, "netmask": a.netmask,
                             "broadcast": a.broadcast})
        output.append({
            "name": name, "ipv4": ipv4,
            "is_up": bool(stats and stats.isup),
            "speed_mbps": stats.speed if stats else 0,
            "mtu": stats.mtu if stats else None
        })
    return output

def validate_network(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("صيغة الشبكة غير صحيحة. مثال: 192.168.1.0/24") from exc
    if not net.is_private:
        raise ValueError("الفحص محصور بعناوين الشبكات الخاصة RFC1918.")
    if net.num_addresses > 256:
        raise ValueError("الحد الأقصى /24 (256 عنواناً).")
    if net.version != 4:
        raise ValueError("الإصدار الحالي يدعم IPv4 فقط.")
    return net

def tcp_probe(ip, port, timeout=0.45):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"port": port, "service": PORTS.get(port, "Unknown")}
    except OSError:
        return None

def http_audit(ip, port, use_tls=False, timeout=2.0):
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    result = {"url": url, "reachable": False, "status_code": None,
              "server": None, "security_headers": {}, "findings": []}
    try:
        response = requests.get(
            url, timeout=timeout, verify=False if use_tls else True,
            allow_redirects=False, headers={"User-Agent": USER_AGENT},
            stream=True
        )
        result["reachable"] = True
        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server")
        for h in ("Strict-Transport-Security", "Content-Security-Policy",
                  "X-Content-Type-Options", "X-Frame-Options",
                  "Referrer-Policy"):
            result["security_headers"][h] = response.headers.get(h)
        if use_tls and not response.headers.get("Strict-Transport-Security"):
            result["findings"].append({
                "severity": "low", "title": "HSTS header absent",
                "detail": "HTTPS endpoint did not return Strict-Transport-Security."
            })
        if not response.headers.get("X-Content-Type-Options"):
            result["findings"].append({
                "severity": "info", "title": "X-Content-Type-Options absent",
                "detail": "Header not observed; applicability depends on the web UI."
            })
        if result["server"]:
            result["findings"].append({
                "severity": "info", "title": "Server banner disclosed",
                "detail": f"HTTP Server header: {result['server'][:120]}"
            })
        response.close()
    except requests.RequestException as exc:
        result["error"] = str(exc)[:180]
    return result

def tls_audit(ip, port, timeout=2.0):
    out = {"port": port, "checked": False, "certificate": None, "findings": []}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                cert = tls.getpeercert()
                out["checked"] = True
                out["tls_version"] = tls.version()
                out["cipher"] = tls.cipher()[0] if tls.cipher() else None
                out["certificate"] = {
                    "subject": str(cert.get("subject")),
                    "issuer": str(cert.get("issuer")),
                    "not_after": cert.get("notAfter")
                }
    except ssl.SSLCertVerificationError as exc:
        out["findings"].append({
            "severity": "medium", "title": "TLS certificate validation failed",
            "detail": str(exc)[:180]
        })
    except (OSError, ssl.SSLError) as exc:
        out["error"] = str(exc)[:180]
    return out

def rtsp_options(ip, port=554, timeout=1.5):
    result = {"port": port, "checked": False, "response": None, "findings": []}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            request = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                f"User-Agent: {USER_AGENT}\r\n\r\n"
            )
            s.sendall(request.encode("ascii"))
            data = s.recv(2048).decode("latin-1", errors="replace")
            result["checked"] = True
            result["response"] = data[:700]
            first = data.splitlines()[0] if data.splitlines() else ""
            if "200" in first:
                result["findings"].append({
                    "severity": "info", "title": "RTSP OPTIONS accepted",
                    "detail": "The RTSP service responded to a non-authenticating OPTIONS request."
                })
    except OSError as exc:
        result["error"] = str(exc)[:160]
    return result

def classify(ports):
    nums = {p["port"] for p in ports}
    if 554 in nums or 8899 in nums:
        return "كاميرا IP محتملة"
    if 37777 in nums or 34567 in nums:
        return "DVR/NVR محتمل"
    if nums.intersection({80, 443, 8080, 8081, 8443}):
        return "جهاز بواجهة ويب"
    return "جهاز شبكة"

def scan_host(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(tcp_probe, ip, port) for port in PORTS]
        for future in as_completed(futures):
            item = future.result()
            if item:
                open_ports.append(item)
    if not open_ports:
        return None

    open_ports.sort(key=lambda x: x["port"])
    device = {
        "id": str(uuid.uuid4()),
        "ip": ip,
        "type": classify(open_ports),
        "ports": open_ports,
        "http": [],
        "tls": [],
        "rtsp": None,
        "findings": [],
        "checked_at": datetime.now(timezone.utc).isoformat()
    }
    for item in open_ports:
        port = item["port"]
        if port in (80, 8000, 8080, 8081, 5000):
            device["http"].append(http_audit(ip, port, False))
        elif port in (443, 8443):
            device["http"].append(http_audit(ip, port, True))
            device["tls"].append(tls_audit(ip, port))
        elif port == 554:
            device["rtsp"] = rtsp_options(ip, port)
    for h in device["http"]:
        device["findings"].extend(h.get("findings", []))
    for t in device["tls"]:
        device["findings"].extend(t.get("findings", []))
    if device["rtsp"]:
        device["findings"].extend(device["rtsp"].get("findings", []))
    return device

def run_scan(cidr, progress=None):
    net = validate_network(cidr)
    targets = [str(ip) for ip in net.hosts()]
    results = []
    completed = 0
    lock = threading.Lock()

    def update():
        if progress:
            progress(completed, len(targets))

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(scan_host, ip): ip for ip in targets}
        for future in as_completed(futures):
            try:
                item = future.result()
                if item:
                    results.append(item)
            except Exception:
                pass
            with lock:
                completed += 1
                update()

    results.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    report = {
        "application": "CCTV Security Auditor X",
        "version": "1.0.0",
        "network": str(net),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "devices_found": len(results),
        "devices": results,
        "note": "Service fingerprints and findings are indicators, not proof of a vulnerability."
    }
    path = REPORT_DIR / f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    report["report_file"] = path.name
    return report

def list_reports():
    items = []
    for p in sorted(REPORT_DIR.glob("assessment_*.json"), reverse=True):
        items.append({"filename": p.name, "size": p.stat().st_size})
    return items

def read_report(filename):
    if Path(filename).name != filename or not filename.endswith(".json"):
        raise ValueError("Invalid report name")
    path = REPORT_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(filename)
    return json.loads(path.read_text(encoding="utf-8"))
