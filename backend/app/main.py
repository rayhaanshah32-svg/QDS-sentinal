from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.endpoints import router as layer1_router
from app.layer2_threat.api import router as layer2_router
from app.api.ops_endpoints import router as ops_router
from app.schemas.api import HealthResponse
from app.database.session import init_db

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="QDS Sentinel - Research-grade Quantum Digital Signatures Security Simulation Engine (Layer 1: Protocol Simulation + Layer 2: Threat Detection)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    init_db()


app.include_router(layer1_router)
app.include_router(layer2_router)
app.include_router(ops_router)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Service Health Check",
    description="Returns the service operational status, application name, version, and active architectural layer.",
)
def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        app_name=settings.app_name,
        version=settings.app_version,
        layer="Layer 1: Protocol Simulation + Layer 2: Threat Detection",
    )
