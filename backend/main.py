"""IIFVDCAS Backend — FastAPI Application, Phase 1: IoT Device Detection"""
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio, logging
from datetime import datetime, timezone
from core.device_detection.detector import (
    run_full_device_scan, get_device_details,
    scan_usb_serial_devices, scan_network_devices, asdict,
)
logging.basicConfig(level=logging.INFO)
app = FastAPI(title="IIFVDCAS API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
scan_cache = {}
active_connections = []

async def broadcast(msg):
    dead = []
    for ws in active_connections:
        try: await ws.send_json(msg)
        except: dead.append(ws)
    for ws in dead: active_connections.remove(ws)

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
    return {"name":"IIFVDCAS API","version":"0.1.0","phase":"Phase 1 — IoT Device Detection","status":"running","timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/health")
async def health():
    return {"status":"ok","timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/api/v1/devices")
async def list_devices():
    devices = scan_usb_serial_devices()
    return {"devices":[asdict(d) for d in devices],"total":len(devices),"timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/api/v1/devices/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = f"scan_{int(datetime.now(timezone.utc).timestamp())}"
    async def _run():
        await broadcast({"event":"scan_started","scan_id":scan_id})
        await broadcast({"event":"scan_progress","scan_id":scan_id,"step":"usb","message":"Scanning USB/Serial devices..."})
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: run_full_device_scan(include_network=request.include_network, subnet=request.subnet))
        result_dict = asdict(result)
        scan_cache[scan_id] = result_dict
        await broadcast({"event":"scan_complete","scan_id":scan_id,"total_found":result.total_found,"duration_ms":result.scan_duration_ms,"result":result_dict})
    background_tasks.add_task(_run)
    return {"scan_id":scan_id,"status":"started","message":"Scan started. Connect to /ws for live progress."}

@app.get("/api/v1/devices/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found or still running")
    return scan_cache[scan_id]

@app.get("/api/v1/devices/{port:path}/details")
async def device_details(port: str):
    if not port.startswith("/dev/"): port = f"/dev/{port}"
    try:
        return {"port":port,"details":get_device_details(port),"timestamp":datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/devices/network/scan")
async def network_scan(subnet: Optional[str] = None):
    devices = scan_network_devices(subnet)
    return {"devices":[asdict(d) for d in devices],"total":len(devices),"subnet_scanned":subnet or "auto","timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/api/v1/system/info")
async def system_info():
    import shutil
    tools = {t: shutil.which(t) is not None for t in ["binwalk","unblob","nmap","checksec","john","avrdude","qemu-arm-static","openssl","shellcheck","udevadm"]}
    return {"tools":tools,"available_phases":{"phase1_device_detection":tools["udevadm"],"phase2_firmware_extraction":tools["binwalk"],"phase3_static_analysis":tools["checksec"],"phase8_dynamic_analysis":tools["qemu-arm-static"]},"timestamp":datetime.now(timezone.utc).isoformat()}
