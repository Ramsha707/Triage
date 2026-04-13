"""
IOC (Indicator of Compromise) Detection API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from database.database import get_db
from database.models import IOC, Case

router = APIRouter()


# Pydantic Schemas
class IOCResponse(BaseModel):
    id: int
    case_id: str
    ioc_type: str
    value: str
    source: Optional[str]
    confidence: float
    severity: str
    description: Optional[str]
    is_malicious: bool
    rule_matched: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class IOCCreate(BaseModel):
    ioc_type: str  # hash, ip, domain, url, file_path, registry_key, mutex
    value: str
    source: Optional[str] = None
    confidence: float = 0.0
    severity: str = "medium"
    description: Optional[str] = None
    is_malicious: bool = False
    rule_matched: Optional[str] = None


class IOCMatchRequest(BaseModel):
    """Submit indicators for matching against threat intelligence"""
    hashes: Optional[List[str]] = None
    ips: Optional[List[str]] = None
    domains: Optional[List[str]] = None


@router.get("/", response_model=List[IOCResponse])
async def get_iocs(
    case_id: str = Query(...),
    ioc_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    is_malicious: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get IOCs for a case with optional filtering"""
    query = select(IOC).where(IOC.case_id == case_id)

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if severity:
        query = query.where(IOC.severity == severity)
    if is_malicious is not None:
        query = query.where(IOC.is_malicious == is_malicious)

    query = query.order_by(IOC.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats")
async def get_ioc_stats(case_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    """Get IOC statistics for a case"""
    total = (await db.execute(select(func.count(IOC.id)).where(IOC.case_id == case_id))).scalar()
    malicious = (await db.execute(select(func.count(IOC.id)).where(
        IOC.case_id == case_id, IOC.is_malicious == True
    ))).scalar()

    # By severity
    severity_query = select(IOC.severity, func.count(IOC.id)).where(
        IOC.case_id == case_id
    ).group_by(IOC.severity)
    severity_result = await db.execute(severity_query)
    by_severity = {row[0]: row[1] for row in severity_result.all()}

    # By type
    type_query = select(IOC.ioc_type, func.count(IOC.id)).where(
        IOC.case_id == case_id
    ).group_by(IOC.ioc_type)
    type_result = await db.execute(type_query)
    by_type = {row[0]: row[1] for row in type_result.all()}

    return {
        "total": total or 0,
        "malicious": malicious or 0,
        "by_severity": by_severity,
        "by_type": by_type,
    }


@router.post("/", response_model=IOCResponse, status_code=status.HTTP_201_CREATED)
async def create_ioc(ioc_data: IOCCreate, db: AsyncSession = Depends(get_db)):
    """Create a new IOC"""
    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == ioc_data.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    db_ioc = IOC(**ioc_data.model_dump())
    db.add(db_ioc)
    await db.commit()
    await db.refresh(db_ioc)

    return db_ioc


@router.post("/scan")
async def scan_for_iocs(
    case_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Run IOC scanning on a case's artifacts
    This checks artifacts against known IOC patterns and threat intelligence
    """
    from services.ioc_scanner import IOCScanner

    scanner = IOCScanner()
    results = await scanner.scan_case(case_id, db)

    return {
        "case_id": case_id,
        "iocs_found": len(results.get("iocs", [])),
        "malicious_count": len([i for i in results.get("iocs", []) if i.get("is_malicious")]),
        "scan_details": results,
    }


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: int, db: AsyncSession = Depends(get_db)):
    """Get specific IOC by ID"""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    return ioc


@router.put("/{ioc_id}", response_model=IOCResponse)
async def update_ioc(ioc_id: int, ioc_data: IOCCreate, db: AsyncSession = Depends(get_db)):
    """Update an IOC"""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    update_data = ioc_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(ioc, field, value)

    await db.commit()
    await db.refresh(ioc)

    return ioc


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(ioc_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an IOC"""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    await db.delete(ioc)
    await db.commit()

    return None
