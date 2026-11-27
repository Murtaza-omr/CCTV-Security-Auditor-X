import threading
import uuid
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from . import scanner

app = FastAPI(title="CCTV Security Auditor X", version="1.0.0")
state = {
    "running": False, "scan_id": None, "progress": 0,
    "total": 0, "status": "جاهز", "result": None, "error": None
}
state_lock = threading.Lock()

class ScanRequest(BaseModel):
    network: str = Field(min_length=9, max_length=30)

def scan_worker(cidr, scan_id):
    def progress(done, total):
        with state_lock:
            state["progress"] = done
            state["total"] = total
            state["status"] = f"يفحص {done}/{total}"
    try:
        report = scanner.run_scan(cidr, progress)
        with state_lock:
            if state["scan_id"] == scan_id:
                state["result"] = report
                state["status"] = "اكتمل الفحص"
    except Exception as exc:
        with state_lock:
            state["error"] = str(exc)
            state["status"] = "فشل الفحص"
    finally:
        with state_lock:
            state["running"] = False

@app.get("/", response_class=HTMLResponse)
def dashboard():
    html = Path(__file__).parent / "static" / "index.html"
    return html.read_text(encoding="utf-8")

@app.get("/api/status")
def status():
    with state_lock:
        return dict(state)

@app.get("/api/adapters")
def adapters():
    return scanner.adapters()

@app.post("/api/scan")
def start_scan(req: ScanRequest):
    try:
        scanner.validate_network(req.network)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    with state_lock:
        if state["running"]:
            raise HTTPException(409, "يوجد فحص قيد التشغيل")
        scan_id = str(uuid.uuid4())
        state.update({
            "running": True, "scan_id": scan_id, "progress": 0,
            "total": 0, "status": "بدأ الفحص", "result": None, "error": None
        })
    threading.Thread(target=scan_worker, args=(req.network, scan_id), daemon=True).start()
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/results")
def results():
    with state_lock:
        return state.get("result") or {"devices_found": 0, "devices": []}

@app.get("/api/reports")
def reports():
    return scanner.list_reports()

@app.get("/api/reports/{filename}")
def report(filename: str):
    try:
        return JSONResponse(scanner.read_report(filename))
    except FileNotFoundError:
        raise HTTPException(404, "Report not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
