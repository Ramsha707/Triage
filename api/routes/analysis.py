"""
AI/ML Analysis API Routes
Anomaly detection, risk prediction, and behavioral analysis
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from database.database import get_db
from database.models import AnalysisResult, Case, Artifact

router = APIRouter()


# Pydantic Schemas
class AnalysisResultResponse(BaseModel):
    id: int
    case_id: str
    analysis_type: str
    model_name: str
    model_version: Optional[str]
    results: dict
    confidence_score: Optional[float]
    anomalies_detected: int
    recommendations: list
    created_at: datetime

    class Config:
        from_attributes = True


class AnomalyDetectionRequest(BaseModel):
    case_id: str
    include_files: bool = True
    include_registry: bool = True
    include_network: bool = True
    sensitivity: str = "medium"  # low, medium, high


class RiskPredictionRequest(BaseModel):
    case_id: str


class BehavioralAnalysisRequest(BaseModel):
    case_id: str
    analyze_patterns: List[str] = ["file_access", "login_times", "network_connections"]


@router.post("/anomaly-detection", response_model=AnalysisResultResponse)
async def run_anomaly_detection(
    request: AnomalyDetectionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Run anomaly detection using Isolation Forest algorithm

    Detects unusual patterns in:
    - File access patterns
    - Registry modifications
    - Network connections
    """
    from services.ai_engine import AIEngine

    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == request.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    engine = AIEngine()
    analysis_result = await engine.detect_anomalies(request, db)

    return analysis_result


@router.post("/risk-prediction", response_model=AnalysisResultResponse)
async def run_risk_prediction(
    request: RiskPredictionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Predict overall risk score using ML model

    Analyzes:
    - Artifact characteristics
    - IOC matches
    - Behavioral patterns
    """
    from services.ai_engine import AIEngine

    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == request.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    engine = AIEngine()
    analysis_result = await engine.predict_risk(request, db)

    # Update case risk score
    risk_score = analysis_result.results.get("overall_risk_score", 0)
    if risk_score >= 75:
        case.risk_level = "critical"
    elif risk_score >= 50:
        case.risk_level = "high"
    elif risk_score >= 25:
        case.risk_level = "medium"
    else:
        case.risk_level = "low"

    case.risk_score = risk_score
    await db.commit()

    return analysis_result


@router.post("/behavioral-analysis", response_model=AnalysisResultResponse)
async def run_behavioral_analysis(
    request: BehavioralAnalysisRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyze behavioral patterns in the case data

    Looks for:
    - Unusual file access times
    - Abnormal login patterns
    - Suspicious network activity
    """
    from services.ai_engine import AIEngine

    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == request.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    engine = AIEngine()
    analysis_result = await engine.analyze_behavior(request, db)

    return analysis_result


@router.get("/results")
async def get_analysis_results(
    case_id: str = Query(...),
    analysis_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get analysis results for a case"""
    query = select(AnalysisResult).where(AnalysisResult.case_id == case_id)

    if analysis_type:
        query = query.where(AnalysisResult.analysis_type == analysis_type)

    query = query.order_by(AnalysisResult.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/summary")
async def get_analysis_summary(case_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    """Get summary of all analysis for a case"""
    # Get latest analysis of each type
    query = select(AnalysisResult).where(AnalysisResult.case_id == case_id)
    result = await db.execute(query)
    analyses = result.scalars().all()

    summary = {
        "case_id": case_id,
        "total_analyses": len(analyses),
        "analyses_by_type": {},
        "total_anomalies": sum(a.anomalies_detected for a in analyses),
        "recommendations": [],
    }

    for analysis in analyses:
        if analysis.analysis_type not in summary["analyses_by_type"]:
            summary["analyses_by_type"][analysis.analysis_type] = {
                "count": 0,
                "latest": None,
                "confidence": None,
            }
        summary["analyses_by_type"][analysis.analysis_type]["count"] += 1
        summary["analyses_by_type"][analysis.analysis_type]["latest"] = analysis.created_at
        summary["analyses_by_type"][analysis.analysis_type]["confidence"] = analysis.confidence_score
        summary["recommendations"].extend(analysis.recommendations)

    return summary


@router.get("/{result_id}", response_model=AnalysisResultResponse)
async def get_analysis_result(result_id: int, db: AsyncSession = Depends(get_db)):
    """Get specific analysis result by ID"""
    result = await db.execute(select(AnalysisResult).where(AnalysisResult.id == result_id))
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis result not found")

    return analysis


@router.delete("/{result_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis_result(result_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an analysis result"""
    result = await db.execute(select(AnalysisResult).where(AnalysisResult.id == result_id))
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis result not found")

    await db.delete(analysis)
    await db.commit()

    return None
