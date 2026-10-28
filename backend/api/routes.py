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
    RobustnessSweepRequest,
    RobustnessRunResponse,
    ObservationPlanResponse,
    AnalyzePcapRequest,
    AnalyzePcapResponse,
    LineageVerifyResponse,
    LineageEventItem,
    EvidenceBundleResponse,
)
from backend.services.pcap_resolver import PcapSecurityError
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


@router.post("/alerts/analyze-pcap", response_model=AnalyzePcapResponse)
def analyze_pcap_file(req: AnalyzePcapRequest):
    mgr = get_manager()
    try:
        res = mgr.analyze_and_record_pcap(req.pcap_path)
        return res
    except PcapSecurityError as pse:
        raise HTTPException(status_code=403, detail=str(pse))
    except (FileNotFoundError, ValueError) as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


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


# ==============================================================================
# EVIDENCE RESILIENCE ENGINE (ERE) / LENS API ENDPOINTS
# ==============================================================================

@router.post("/lens/robustness-runs", response_model=RobustnessRunResponse)
def create_robustness_sweep(req: RobustnessSweepRequest):
    mgr = get_manager()
    try:
        run = mgr.robustness_sweep.create_sweep_run(
            pcap_path=req.pcap_path,
            loss_modes=req.loss_modes,
            drop_rates=req.drop_rates,
            seeds=req.seeds,
            burst_configs=req.burst_configs,
            drop_ips=req.drop_ips,
            max_runs=req.max_runs,
        )
        try:
            mgr.lineage_service.record_event(
                event_type="ROBUSTNESS_SWEEP_QUEUED",
                manifest_data={
                    "run_id": run.run_id,
                    "pcap_name": run.pcap_name,
                    "pcap_sha256": run.pcap_sha256,
                    "total_scenarios": run.total_scenarios,
                    "loss_modes": req.loss_modes,
                    "drop_rates": req.drop_rates,
                    "seeds": req.seeds,
                },
                parent_id=None,
                event_id=f"lin-{run.run_id}",
            )
        except Exception:
            pass

        return run.to_dict()
    except PcapSecurityError as pse:
        raise HTTPException(status_code=403, detail=str(pse))
    except (FileNotFoundError, ValueError) as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sweep execution error: {e}")


@router.get("/lens/robustness-runs")
def list_robustness_sweeps():
    mgr = get_manager()
    return mgr.robustness_sweep.list_sweep_runs()


@router.get("/lens/robustness-runs/{run_id}", response_model=RobustnessRunResponse)
def get_robustness_sweep(run_id: str):
    mgr = get_manager()
    run = mgr.robustness_sweep.get_sweep_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Robustness sweep '{run_id}' not found")
    return run


@router.post("/lens/robustness-runs/{run_id}/cancel")
def cancel_robustness_sweep(run_id: str):
    mgr = get_manager()
    success = mgr.robustness_sweep.cancel_sweep_run(run_id)
    if not success:
        raise HTTPException(status_code=400, detail=f"Could not cancel sweep '{run_id}' (not found or already finished)")
    return {"status": "cancelled", "run_id": run_id}


@router.get("/lens/robustness-runs/{run_id}/report")
def get_robustness_sweep_report(run_id: str):
    mgr = get_manager()
    run = mgr.robustness_sweep.get_sweep_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Robustness sweep '{run_id}' not found")
    if run.get("status") != "completed":
        raise HTTPException(status_code=400, detail=f"Sweep '{run_id}' is in state '{run.get('status')}', report not ready")

    report = {
        "report_version": "netguard-robustness-v1",
        "generated_at": time.time(),
        "run_id": run["run_id"],
        "source_capture": {
            "pcap_name": run["pcap_name"],
            "pcap_sha256": run["pcap_sha256"],
            "pcap_size_bytes": run["pcap_size_bytes"],
        },
        "detector_state": {
            "model_available": mgr.detector.model_available,
            "model_scope": getattr(mgr.detector, "model_scope", "synthetic-demo" if mgr.detector.model_available else "rule-fallback"),
            "threshold": mgr.detector.threshold,
        },
        "stability_verdict": run["stability_verdict"],
        "robustness_envelope": run["envelope"],
        "atlas_matrix": run["atlas_matrix"],
        "baseline_summary": run["baseline_summary"],
        "scenarios_evaluated": run["total_scenarios"],
        "completed_scenarios": run["completed_scenarios"],
        "scenarios": run["scenario_results"],
        "disclaimer": "Advisory counterfactual measurement within tested parameter boundaries. Real-world packet loss may exhibit unmodelled temporal or payload correlations."
    }
    return report


@router.get("/lens/alerts/{alert_id}/observation-plan", response_model=ObservationPlanResponse)
def get_alert_observation_plan(alert_id: str, run_id: Optional[str] = Query(None)):
    mgr = get_manager()
    incident = mgr.repository.get_incident_by_id(alert_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Alert/Incident '{alert_id}' not found")

    sweep_run_dict = mgr.robustness_sweep.get_sweep_run(run_id) if run_id else None

    plan = mgr.observation_planner.generate_plan(
        passport=incident,
        sweep_run=sweep_run_dict
    )

    try:
        mgr.lineage_service.record_event(
            event_type="OBSERVATION_PLAN_GENERATED",
            manifest_data={
                "plan_id": plan.plan_id,
                "target_alert_id": alert_id,
                "run_id": run_id,
                "plan_mode": plan.plan_mode,
                "total_recommendations": plan.total_recommendations,
                "recommendation_ids": [r["recommendation_id"] for r in plan.recommendations],
            },
            parent_id=alert_id,
        )
    except Exception:
        pass

    return plan.to_dict()


@router.get("/lens/sweeps/{run_id}/observation-plan", response_model=ObservationPlanResponse)
def get_sweep_observation_plan(run_id: str):
    mgr = get_manager()
    sweep_run_dict = mgr.robustness_sweep.get_sweep_run(run_id)
    if not sweep_run_dict:
        raise HTTPException(status_code=404, detail=f"Robustness sweep '{run_id}' not found")

    plan = mgr.observation_planner.generate_plan(
        passport=None,
        sweep_run=sweep_run_dict
    )

    try:
        mgr.lineage_service.record_event(
            event_type="OBSERVATION_PLAN_GENERATED",
            manifest_data={
                "plan_id": plan.plan_id,
                "target_alert_id": None,
                "run_id": run_id,
                "plan_mode": plan.plan_mode,
                "status": plan.status,
                "total_recommendations": plan.total_recommendations,
                "recommendation_ids": [r["recommendation_id"] for r in plan.recommendations],
            },
            parent_id=f"lin-{run_id}",
        )
    except Exception:
        pass

    return plan.to_dict()


@router.get("/lens/observation-plan", response_model=ObservationPlanResponse)
def get_observation_plan(alert_id: Optional[str] = Query(None), run_id: Optional[str] = Query(None)):
    if alert_id:
        return get_alert_observation_plan(alert_id=alert_id, run_id=run_id)
    elif run_id:
        return get_sweep_observation_plan(run_id=run_id)
    else:
        mgr = get_manager()
        plan = mgr.observation_planner.generate_plan(passport=None, sweep_run=None)
        return plan.to_dict()


@router.get("/lens/lineage/verify", response_model=LineageVerifyResponse)
def verify_lineage_chain():
    mgr = get_manager()
    return mgr.lineage_service.verify_chain()


@router.get("/lens/lineage/events")
def list_lineage_events(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    mgr = get_manager()
    events, total = mgr.lineage_service.list_events(limit=limit, offset=offset)
    return {
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/lens/lineage/{event_id}", response_model=LineageEventItem)
def get_lineage_event(event_id: str):
    mgr = get_manager()
    event = mgr.lineage_service.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Lineage event '{event_id}' not found")
    return event


@router.get("/lens/evidence-bundle/{run_or_event_id}", response_model=EvidenceBundleResponse)
def get_evidence_bundle(run_or_event_id: str):
    mgr = get_manager()
    bundle = mgr.lineage_service.build_evidence_bundle(run_or_event_id)
    return bundle
