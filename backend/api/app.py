"""FastAPI application factory for the NetGuard Observatory."""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from backend.api.capture_manager import CaptureManager
from backend.api.routes import router, set_capture_manager

capture_manager_instance: CaptureManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global capture_manager_instance
    # Initialize manager in deterministic demo mode by default
    capture_manager_instance = CaptureManager()
    set_capture_manager(capture_manager_instance)
    # Start default demo capture so reviewer has live updating data out-of-the-box
    try:
        capture_manager_instance.start_capture(mode="demo")
    except Exception as e:
        print(f"Initial demo start note: {e}")
    yield
    if capture_manager_instance:
        capture_manager_instance.stop_capture()


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetGuard — Evidence-Aware Network Threat Observatory",
        description="Network Threat Observatory with Capture-Aware Incident Verification",
        version="1.0.0",
        lifespan=lifespan
    )

    # Scoped CORS for local frontend console
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)

    # Mount built frontend if available
    dist_dir = Path("frontend/dist")
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="frontend")

    return app


app = create_app()
