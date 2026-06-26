"""IIFVDCAS Backend — FastAPI App (Phases 1–7)"""
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
from core.static_analysis.routes    import router as analysis_router
from core.sbom.routes               import router as sbom_router
from core.cve_mapping.routes        import router as cve_router
from core.vex_engine.routes         import router as vex_router
from core.compliance.routes         import router as compliance_router
from core.ai.routes                 import router as ai_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="IIFVDCAS API", version="0.7.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
app.include_router(firmware_router)
app.include_router(analysis_router)
app.include_router(sbom_router)
app.include_router(cve_router)
app.include_router(vex_router)
app.include_router(compliance_router)
app.include_router(ai_router)

scan_cache: dict = {}
active_connections: list[WebSocket] = []


async def broadcast(msg: dict):
    dead = []
    for ws in active_connections:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in active_connections:
            active_connections.remove(ws)


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


@app.on_event("startup")
async def startup_warmup():
    loop = asyncio.get_event_loop()
    async def _warm():
        try:
            from core.cve_mapping.nvd_lookup import _get_conn, DB_PATH
            if not DB_PATH.exists():
                return
            conn = await loop.run_in_executor(None, _get_conn)
            if conn:
                for product in ("openssl", "linux_kernel", "busybox", "wolfssl"):
                    await loop.run_in_executor(
                        None,
                        lambda p=product: conn.execute(
                            "SELECT count(*) FROM cpe WHERE product=?", (p,)
                        ).fetchone(),
                    )
                logger.info("[startup] NVD index warm-up complete")
        except Exception as e:
            logger.warning(f"[startup] NVD warm-up: {e}")
    asyncio.create_task(_warm())


class ScanRequest(BaseModel):
    include_network: bool = False
    subnet: Optional[str] = None


@app.get("/")
async def root():
    return {
        "name": "IIFVDCAS API", "version": "0.8.0",
        "phases": "1-Device · 2-Extraction · 3-Static · 4-SBOM · 5-CVE · 6-VEX · 7-Compliance · AI-Assistant",
        "status": "running",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/v1/devices")
async def list_devices():
    devices = scan_usb_serial_devices()
    return {
        "devices":   [asdict(d) for d in devices],
        "total":     len(devices),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/devices/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = f"scan_{int(datetime.now(timezone.utc).timestamp())}"
    async def _run():
        await broadcast({"event": "scan_started", "scan_id": scan_id})
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: run_full_device_scan(
                include_network=request.include_network,
                subnet=request.subnet,
            ),
        )
        result_dict = asdict(result)
        scan_cache[scan_id] = result_dict
        await broadcast({
            "event": "scan_complete", "scan_id": scan_id,
            "total_found": result.total_found, "result": result_dict,
        })
    background_tasks.add_task(_run)
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/v1/devices/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scan_cache:
        raise HTTPException(404, "Scan not found")
    return scan_cache[scan_id]


@app.get("/api/v1/devices/{port:path}/details")
async def device_details(port: str):
    if not port.startswith("/dev/"):
        port = f"/dev/{port}"
    return {"port": port, "details": get_device_details(port)}


@app.get("/api/v1/devices/network/scan")
async def network_scan(subnet: Optional[str] = None):
    devices = scan_network_devices(subnet)
    return {"devices": [asdict(d) for d in devices], "total": len(devices)}


@app.get("/api/v1/system/info")
async def system_info():
    tools = {
        t: shutil.which(t) is not None
        for t in [
            "binwalk","unblob","nmap","checksec","john","avrdude",
            "esptool","openssl","shellcheck","udevadm","file","objdump",
            "avr-objdump","avr-objcopy","strings",
        ]
    }
    from core.cve_mapping.nvd_lookup import DB_PATH
    return {
        "tools": tools,
        "nvd_index_ready": DB_PATH.exists(),
        "available_phases": {
            "phase1": True,
            "phase2": tools.get("avrdude", False) or tools.get("esptool", False),
            "phase3": tools.get("checksec", False),
            "phase4": True,
            "phase5": True,
            "phase6": True,
            "phase7": True,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
