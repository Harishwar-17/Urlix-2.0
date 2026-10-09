import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer import URLExplainableAnalyzer

app = FastAPI(
    title="URLIX API",
    description="URLIX Phishing & Malicious Link Detection Engine Backend",
    version="0.2.0",
)

# Startup timestamp for uptime calculation
START_TIME = time.time()

# Shared singleton analyzer engine
analyzer = URLExplainableAnalyzer()

# Configure CORS for frontend access
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL string to passively inspect (HTTP/HTTPS)")

class FindingModel(BaseModel):
    rule_id: str
    title: str
    severity: str  # 'info', 'low', 'medium', 'high'
    score_impact: int
    evidence: str
    explanation: str

class AnalyzeResponse(BaseModel):
    submitted_url: str
    normalized_url: str
    scheme: str
    hostname: str
    registered_domain: str
    path: str
    risk_category: str  # 'Low', 'Medium', 'High'
    heuristic_score: int  # 0 to 100
    score_description: str
    summary: str
    findings_count: int
    findings: List[FindingModel]
    recommendations: List[str]
    disclaimer: str
    analyzed_at: str
    passive_analysis: bool
    threat_tags: Optional[List[str]] = None
    defanged_url: Optional[str] = None

class DefangRequest(BaseModel):
    url: str

class BulkAnalyzeRequest(BaseModel):
    urls: Optional[List[str]] = None
    text: Optional[str] = None

@app.get("/")
def read_root():
    return {
        "service": "URLIX API",
        "tagline": "See the Link. Spot the Threat.",
        "status": "operational",
        "health_endpoint": "/api/health",
        "analyze_endpoint": "/api/analyze",
        "documentation": "/docs",
    }

@app.get("/api/health")
def get_health():
    """
    Health check endpoint returning system status, service info,
    and server uptime.
    """
    now = datetime.now(timezone.utc)
    uptime = round(time.time() - START_TIME, 2)
    return {
        "status": "healthy",
        "service": "URLIX Detection Engine",
        "tagline": "See the Link. Spot the Threat.",
        "version": "0.2.0",
        "timestamp": now.isoformat(),
        "uptime_seconds": uptime,
        "environment": "development",
        "detection_engine": "active_milestone_2",
    }

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_url(payload: AnalyzeRequest):
    """
    Passively inspects submitted URL using explainable lexical & structural heuristics.
    Never opens, requests, or executes the target destination.
    """
    url_input = payload.url.strip() if payload.url else ""
    if not url_input:
        raise HTTPException(
            status_code=400,
            detail="URL parameter is required and cannot be empty."
        )

    try:
        result = analyzer.analyze(url_input)
        return result
    except ValueError as err:
        raise HTTPException(
            status_code=400,
            detail=str(err)
        )
    except Exception as err:
        raise HTTPException(
            status_code=500,
            detail=f"Internal analysis error: {str(err)}"
        )
