"""IIFVDCAS Backend — FastAPI App (Phase 1 + 2 + 3)"""
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio, logging, shutil
from datetime import datetime, timezone

from core.device_detection.detector import (
    run_full_device_scan, get_device_details,
    scan_usb_serial_devices, scan_network_devices, asdict,
)
from core.firmware_extraction.routes import router as firmware_router
from core.static_analysis.routes import router as analysis_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="IIFVDCAS API", version="0.3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(firmware_router)
app.include_router(analysis_router)

scan_cache = {}
active_connections: list[WebSocket] = []


async def broadcast(msg: dict):
    dead = []
    for ws in active_connections:
        try: await ws.send_json(msg)
        except: dead.append(ws)
    for ws in dead:
        if ws in active_connections: active_connections.remove(ws)


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections: active_connections.remove(websocket)


class ScanRequest(BaseModel):
    include_network: bool = False
    subnet: Optional[str] = None


@app.get("/")
async def root():
    return {"name": "IIFVDCAS API", "version": "0.3.0",
            "phases": "Phase 1 (Device) + Phase 2 (Extraction) + Phase 3 (Static Analysis)",
            "status": "running", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/v1/devices")
async def list_devices():
    devices = scan_usb_serial_devices()
    return {"devices": [asdict(d) for d in devices], "total": len(devices),
            "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/v1/devices/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = f"scan_{int(datetime.now(timezone.utc).timestamp())}"
    async def _run():
        await broadcast({"event": "scan_started", "scan_id": scan_id})
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: run_full_device_scan(
                include_network=request.include_network, subnet=request.subnet))
        result_dict = asdict(result)
        scan_cache[scan_id] = result_dict
        await broadcast({"event": "scan_complete", "scan_id": scan_id,
                         "total_found": result.total_found, "result": result_dict})
    background_tasks.add_task(_run)
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/v1/devices/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scan_cache: raise HTTPException(404, "Scan not found")
    return scan_cache[scan_id]


@app.get("/api/v1/devices/{port:path}/details")
async def device_details(port: str):
    if not port.startswith("/dev/"): port = f"/dev/{port}"
    return {"port": port, "details": get_device_details(port)}


@app.get("/api/v1/devices/network/scan")
async def network_scan(subnet: Optional[str] = None):
    devices = scan_network_devices(subnet)
    return {"devices": [asdict(d) for d in devices], "total": len(devices)}


@app.get("/api/v1/system/info")
async def system_info():
    tools = {t: shutil.which(t) is not None for t in [
        "binwalk","unblob","nmap","checksec","john","avrdude",
        "qemu-arm-static","openssl","shellcheck","udevadm","7z","file","ent",
        "objdump","readelf","bandit","yara","ssdeep"
    ]}
    return {
        "tools": tools,
        "available_phases": {
            "phase1_device_detection":   tools["udevadm"],
            "phase2_firmware_extraction":tools["binwalk"] or tools["unblob"],
            "phase3_static_analysis":    tools["checksec"] and tools["openssl"],
            "phase8_dynamic_analysis":   tools.get("qemu-arm-static", False),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
