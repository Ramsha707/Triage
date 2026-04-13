"""
Case Management API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from database.database import get_db
from database.models import Case

router = APIRouter()


# Pydantic Schemas
class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    investigator: str
    case_id: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None


class CaseResponse(BaseModel):
    id: int
    case_id: str
    title: str
    description: Optional[str]
    investigator: str
    status: str
    risk_score: float
    risk_level: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(case_data: CaseCreate, db: AsyncSession = Depends(get_db)):
    """Create a new investigation case"""

    # Generate case ID if not provided
    if not case_data.case_id:
        year = datetime.now().year
        result = await db.execute(select(func.count(Case.id)))
        count = result.scalar() or 0
        case_id = f"CTF-{year}-{count + 1:04d}"
    else:
        case_id = case_data.case_id

    # Check if case ID already exists
    existing = await db.execute(select(Case).where(Case.case_id == case_id))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Case ID '{case_id}' already exists"
        )

    db_case = Case(
        case_id=case_id,
        title=case_data.title,
        description=case_data.description,
        investigator=case_data.investigator,
    )

    db.add(db_case)
    await db.commit()
    await db.refresh(db_case)

    return db_case


@router.get("/", response_model=List[CaseResponse])
async def get_cases(status_filter: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Get all cases, optionally filtered by status"""
    query = select(Case)
    if status_filter:
        query = query.where(Case.status == status_filter)
    query = query.order_by(Case.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific case by ID"""
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    return case


@router.put("/{case_id}", response_model=CaseResponse)
async def update_case(case_id: str, case_data: CaseUpdate, db: AsyncSession = Depends(get_db)):
    """Update a case"""
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    update_data = case_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(case, field, value)

    await db.commit()
    await db.refresh(case)

    return case


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(case_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a case"""
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    await db.delete(case)
    await db.commit()

    return None
