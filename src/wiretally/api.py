import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
from .validator import validate_capture_file, ValidationError
from .parser import extract_packet_metadata, ParserError
from .analyzer import aggregate_flows
from .rules import run_all_rules
from .cli import find_tshark
app = FastAPI(
    title="WireTally API",
    description="Defensive Network Analysis Workbench Local Service",
    version="0.1.0"
)
# Allow React frontend to communicate with this API locally
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class AnalysisRequest(BaseModel):
    pcap_path: str
class AnalysisResponse(BaseModel):
    status: str
    total_flows: int
    total_findings: int
    findings: List[Dict[str, Any]]
@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_pcap(request: AnalysisRequest):
    tshark_path = find_tshark()
    if not tshark_path:
        raise HTTPException(
            status_code=503,
            detail={"code": "tshark_unavailable", "message": "TShark executable not found on this system."},
        )
    filepath = request.pcap_path
    try:
        validate_capture_file(filepath)
        packets = extract_packet_metadata(tshark_path, filepath)
        flows = aggregate_flows(packets)
        findings = run_all_rules(flows)
        return AnalysisResponse(
            status="success",
            total_flows=len(flows),
            total_findings=len(findings),
            findings=findings
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ParserError as e:
        status_code = 504 if e.code == "tshark_timeout" else 422
        raise HTTPException(status_code=status_code, detail={"code": e.code, "message": str(e)})
    except Exception:
        # Do not expose internal exception text, local file paths, or runtime
        # details to an API caller.
        raise HTTPException(
            status_code=500,
            detail={"code": "analysis_internal_error", "message": "Unexpected internal analysis error."},
        )
@app.get("/")
async def root():
    return {"message": "WireTally API is running."}
