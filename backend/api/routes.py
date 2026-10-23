"""FastAPI typed route definitions for NetGuard Observatory."""
import asyncio
import json
from pathlib import Path
import time
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from backend.capture.packet_capture import list_interfaces
from backend.api.schemas import (
    HealthResponse,
    CaptureStartRequest,
    ReplayStartRequest,
    OverviewResponse,
    HostGraphResponse,
)
from backend.api.capture_manager import CaptureManager

router = APIRouter(prefix="/api")

# Singleton capture manager instance reference set on app creation
_manager: Optional[CaptureManager] = None


def set_capture_manager(mgr: CaptureManager) -> None:
    global _manager
    _manager = mgr


def get_manager() -> CaptureManager:
    if _manager is None:
        raise HTTPException(status_code=500, detail="CaptureManager not initialized")
    return _manager


@router.get("/health", response_model=HealthResponse)
def get_health():
    mgr = get_manager()
    status = mgr.get_status()
    return HealthResponse(
        status="healthy" if not status["error"] else "degraded",
        capture_running=status["running"],
        mode=status["mode"],
        interface=status["interface"],
        model_loaded=status["model_available"],
        model_scope=status["model_scope"],
        uptime_seconds=status["uptime"],
        total_packets=status["total_packets"],
        capture_quality_status=status["capture_quality"]["overall_status"]
    )


@router.get("/interfaces")
def get_interfaces():
    try:
        scapy_ifaces = list_interfaces()
        items = []
        for iface in scapy_ifaces:
            items.append({
                "name": str(iface.name),
                "description": str(getattr(iface, "description", "") or iface.name),
                "ip": str(getattr(iface, "ip", "") or ""),
                "is_default": bool(getattr(iface, "is_default", False))
            })
        return items
    except Exception as e:
        return [{"name": "default", "description": f"Interface enumeration limited ({e})", "ip": "", "is_default": True}]


@router.post("/capture/start")
def start_capture(req: CaptureStartRequest):
    mgr = get_manager()
    try:
        mgr.start_capture(
            mode=req.mode,
            interface=req.interface,
            pcap_path=req.pcap_path,
            capture_filter=req.capture_filter
        )
        return {"status": "started", "mode": req.mode, "interface": mgr.interface}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/capture/stop")
def stop_capture():
    mgr = get_manager()
    mgr.stop_capture()
    return {"status": "stopped", "mode": mgr.mode, "interface": mgr.interface}


@router.get("/overview", response_model=OverviewResponse)
def get_overview():
    mgr = get_manager()
    st = mgr.get_status()
    return OverviewResponse(
        status="CAPTURING" if st["running"] else "STOPPED",
        mode=st["mode"],
        interface=st["interface"],
        uptime_seconds=round(st["uptime"], 1),
        total_packets=st["total_packets"],
        total_bytes=st["total_bytes"],
        packets_per_second=round(st["packets_per_second"], 2),
        bytes_per_second=round(st["bytes_per_second"], 2),
        active_hosts=st["active_hosts"],
        active_flows=st["active_flows"],
        protocols=st["protocols"],
        extended_protocols=st["extended_protocols"],
        rates=st["rates"],
        capture_quality=st["capture_quality"],
        recent_alerts_count=st["recent_alerts_count"],
        total_flows=st.get("total_flows"),
        total_hosts=st.get("total_hosts"),
    )


@router.get("/traffic/timeseries")
def get_timeseries():
    mgr = get_manager()
    return mgr.get_timeseries()


@router.get("/flows")
def get_flows(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    protocol: Optional[str] = None,
    search: Optional[str] = None
):
    mgr = get_manager()
    items, total = mgr.flow_engine.get_flows(limit=limit, offset=offset, protocol=protocol, search=search)
    return {"total": total, "limit": limit, "offset": offset, "flows": items}


@router.get("/flows/{flow_id}")
def get_flow(flow_id: str):
    mgr = get_manager()
    flow = mgr.flow_engine.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow


@router.get("/hosts", response_model=HostGraphResponse)
def get_hosts():
    mgr = get_manager()
    graph = mgr.flow_engine.get_host_graph()
    metrics = mgr.flow_engine.get_metrics()
    return HostGraphResponse(
        nodes=graph["nodes"],
        edges=graph["edges"],
        disclaimer=graph["disclaimer"],
        top_talkers=metrics["top_talkers"]
    )


@router.get("/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    class_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    search: Optional[str] = None,
    redact_ips: bool = False
):
    mgr = get_manager()
    items, total = mgr.repository.get_incidents(
        limit=limit, offset=offset, class_filter=class_filter,
        severity_filter=severity_filter, search=search, redact_ips=redact_ips
    )
    return {"total": total, "limit": limit, "offset": offset, "alerts": items}


@router.get("/alerts/{alert_id}")
def get_alert_passport(alert_id: str, redact_ips: bool = False):
    mgr = get_manager()
    passport = mgr.repository.get_incident_by_id(alert_id, redact_ips=redact_ips)
    if not passport:
        raise HTTPException(status_code=404, detail="Evidence Passport not found")
    return passport


@router.get("/alerts/export/json")
def export_alerts_json(redact_ips: bool = False):
    mgr = get_manager()
    content = mgr.repository.export_json(redact_ips=redact_ips)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=netguard_evidence_export.json"}
    )


@router.get("/alerts/export/csv")
def export_alerts_csv(redact_ips: bool = False):
    mgr = get_manager()
    content = mgr.repository.export_csv(redact_ips=redact_ips)
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netguard_evidence_export.csv"}
    )


@router.get("/replays/pcaps")
def list_pcaps():
    mgr = get_manager()
    return mgr.replay_lab.list_available_pcaps()


@router.post("/replays")
def create_replay(req: ReplayStartRequest):
    mgr = get_manager()
    try:
        exp = mgr.replay_lab.create_experiment(
            pcap_path=req.pcap_path,
            loss_mode=req.loss_mode,
            drop_rate=req.drop_rate,
            seed=req.seed,
            burst_size=req.burst_size,
            burst_interval=req.burst_interval,
            drop_ip=req.drop_ip
        )
        return exp.to_dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/replays")
def list_replays():
    mgr = get_manager()
    return mgr.replay_lab.list_experiments()


@router.get("/replays/{run_id}")
def get_replay(run_id: str):
    mgr = get_manager()
    exp = mgr.replay_lab.get_experiment(run_id)
    if not exp:
        raise HTTPException(status_code=404, detail="Replay experiment not found")
    return exp


@router.post("/replays/{run_id}/cancel")
def cancel_replay(run_id: str):
    mgr = get_manager()
    success = mgr.replay_lab.cancel_experiment(run_id)
    if not success:
        raise HTTPException(status_code=400, detail="Experiment could not be cancelled")
    return {"status": "cancelled", "run_id": run_id}


@router.get("/evaluation")
def get_evaluation():
    report_file = None
    for candidate in [
        Path("artifacts/netguard.report.json"),
        Path("artifacts/demo/model.report.json"),
        Path("artifacts/model.report.json")
    ]:
        if candidate.exists():
            report_file = candidate
            break

    if not report_file:
        return {
            "status": "NOT_EVALUATED",
            "message": "Model evaluation has not been executed yet. Run demo training via CLI or research runner to generate verified metrics.",
            "metrics": None
        }
    try:
        data = json.loads(report_file.read_text())
        return {
            "status": "EVALUATED",
            "scope": data.get("scope", "synthetic-demo"),
            "features": data.get("features", []),
            "threshold": data.get("threshold"),
            "sklearn_version": data.get("sklearn_version"),
            "tests": data.get("tests", {}),
            "disclaimer": "Synthetic benchmark results establish pipeline verification; they do not certify production zero-day defense."
        }
    except Exception as error:
        return {"status": "ERROR", "message": str(error)}


@router.get("/settings")
def get_settings():
    mgr = get_manager()
    return {
        "app_name": "NetGuard Observatory",
        "version": "1.0.0-evidence-aware",
        "host_binding": "127.0.0.1",
        "port": 8000,
        "mode": mgr.mode,
        "interface": mgr.interface,
        "model_loaded": mgr.detector.model_available,
        "anomaly_baseline_ready": mgr.anomaly_detector.is_ready,
        "retention_policy": "Local SQLite (metadata only, no raw packet payloads)",
    }


@router.get("/events")
async def events_sse():
    """Server-Sent Events (SSE) feed for live UI updates with backpressure safety."""
    mgr = get_manager()

    async def event_generator():
        while True:
            try:
                overview = get_overview()
                payload = json.dumps(overview.model_dump())
                yield f"data: {payload}\n\n"
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(1.0)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
