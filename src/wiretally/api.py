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
        raise HTTPException(status_code=500, detail="TShark executable not found on this system.")
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
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
@app.get("/")
async def root():
    return {"message": "WireTally API is running."}
