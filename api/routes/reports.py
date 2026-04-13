"""
Report Generation API Routes
Export findings as PDF, JSON, or CSV
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
import os

from database.database import get_db
from database.models import Report, Case

router = APIRouter()

REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")


# Pydantic Schemas
class ReportResponse(BaseModel):
    id: int
    case_id: str
    report_type: str
    file_path: str
    file_name: str
    file_size: Optional[int]
    generated_by: Optional[str]
    includes: list
    created_at: datetime

    class Config:
        from_attributes = True


class ReportGenerateRequest(BaseModel):
    case_id: str
    report_type: str  # pdf, json, csv
    include_artifacts: bool = True
    include_iocs: bool = True
    include_timeline: bool = True
    include_analysis: bool = True
    generated_by: Optional[str] = None


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a forensic report

    Formats:
    - **PDF**: Professional formatted report with charts
    - **JSON**: Machine-readable format for integration
    - **CSV**: Spreadsheet-friendly format
    """
    from services.report_generator import ReportGenerator

    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == request.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    generator = ReportGenerator()

    # Generate report
    report_data = await generator.generate(request, db)

    # Create report record
    db_report = Report(
        case_id=request.case_id,
        report_type=request.report_type,
        file_path=report_data["file_path"],
        file_name=report_data["file_name"],
        file_size=report_data.get("file_size"),
        generated_by=request.generated_by,
        includes=[
            "artifacts" if request.include_artifacts else None,
            "iocs" if request.include_iocs else None,
            "timeline" if request.include_timeline else None,
            "analysis" if request.include_analysis else None,
        ],
    )
    db_report.includes = [i for i in db_report.includes if i]

    db.add(db_report)
    await db.commit()
    await db.refresh(db_report)

    return db_report


@router.get("/", response_model=List[ReportResponse])
async def get_reports(
    case_id: Optional[str] = Query(None),
    report_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get all reports, optionally filtered by case or type"""
    query = select(Report)
    if case_id:
        query = query.where(Report.case_id == case_id)
    if report_type:
        query = query.where(Report.report_type == report_type)

    query = query.order_by(Report.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{report_id}/download")
async def download_report(report_id: int, db: AsyncSession = Depends(get_db)):
    """Download a generated report file"""
    from fastapi.responses import FileResponse

    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found")

    return FileResponse(
        report.file_path,
        media_type="application/octet-stream",
        filename=report.file_name,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: int, db: AsyncSession = Depends(get_db)):
    """Get report metadata"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return report


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(report_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a report"""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    # Delete file
    if os.path.exists(report.file_path):
        os.remove(report.file_path)

    await db.delete(report)
    await db.commit()

    return None


@router.get("/templates/list")
async def get_report_templates():
    """Get available report templates"""
    return {
        "templates": [
            {
                "id": "standard",
                "name": "Standard Forensic Report",
                "description": "Complete forensic analysis report with all sections",
                "sections": ["executive_summary", "evidence", "artifacts", "iocs", "timeline", "analysis", "recommendations"],
            },
            {
                "id": "executive",
                "name": "Executive Summary",
                "description": "High-level summary for management",
                "sections": ["executive_summary", "risk_score", "key_findings", "recommendations"],
            },
            {
                "id": "technical",
                "name": "Technical Report",
                "description": "Detailed technical findings for analysts",
                "sections": ["evidence", "artifacts", "iocs", "timeline", "analysis", "technical_details"],
            },
            {
                "id": "ioc_export",
                "name": "IOC Export",
                "description": "STIX/TAXII compatible IOC export",
                "sections": ["iocs", "indicators", "malware_signatures"],
            },
        ],
    }
