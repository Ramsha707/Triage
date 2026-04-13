"""
Event Timeline API Routes
Chronological reconstruction of events
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from database.database import get_db
from database.models import TimelineEvent, Case, Artifact

router = APIRouter()


# Pydantic Schemas
class TimelineEventResponse(BaseModel):
    id: int
    case_id: str
    timestamp: datetime
    event_type: str
    description: str
    severity: str
    details: dict
    created_at: datetime

    class Config:
        from_attributes = True


class TimelineEventCreate(BaseModel):
    event_type: str
    description: str
    timestamp: datetime
    severity: str = "info"
    details: dict = {}
    source_artifact_id: Optional[int] = None


class TimelineGenerateRequest(BaseModel):
    case_id: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    event_types: Optional[List[str]] = None


@router.get("/", response_model=List[TimelineEventResponse])
async def get_timeline(
    case_id: str = Query(...),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    Get timeline events for a case

    Events are returned in chronological order
    """
    query = select(TimelineEvent).where(TimelineEvent.case_id == case_id)

    if start_time:
        query = query.where(TimelineEvent.timestamp >= start_time)
    if end_time:
        query = query.where(TimelineEvent.timestamp <= end_time)
    if event_type:
        query = query.where(TimelineEvent.event_type == event_type)
    if severity:
        query = query.where(TimelineEvent.severity == severity)

    query = query.order_by(TimelineEvent.timestamp.asc()).offset(offset).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats")
async def get_timeline_stats(case_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    """Get timeline statistics"""
    total = (await db.execute(select(func.count(TimelineEvent.id)).where(TimelineEvent.case_id == case_id))).scalar()

    # By severity
    severity_query = select(TimelineEvent.severity, func.count(TimelineEvent.id)).where(
        TimelineEvent.case_id == case_id
    ).group_by(TimelineEvent.severity)
    severity_result = await db.execute(severity_query)
    by_severity = {row[0]: row[1] for row in severity_result.all()}

    # By type
    type_query = select(TimelineEvent.event_type, func.count(TimelineEvent.id)).where(
        TimelineEvent.case_id == case_id
    ).group_by(TimelineEvent.event_type)
    type_result = await db.execute(type_query)
    by_type = {row[0]: row[1] for row in type_result.all()}

    # Time range
    time_range = await db.execute(
        select(func.min(TimelineEvent.timestamp), func.max(TimelineEvent.timestamp)).where(
            TimelineEvent.case_id == case_id
        )
    )
    time_result = time_range.first()

    return {
        "total": total or 0,
        "by_severity": by_severity,
        "by_type": by_type,
        "start_time": time_result[0] if time_result else None,
        "end_time": time_result[1] if time_result else None,
    }


@router.post("/generate")
async def generate_timeline(
    request: TimelineGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate timeline from case artifacts

    Automatically creates timeline events from artifact timestamps
    """
    from services.timeline_generator import TimelineGenerator

    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == request.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    generator = TimelineGenerator()
    events = await generator.generate(request, db)

    return {
        "case_id": request.case_id,
        "events_generated": len(events),
        "events": events,
    }


@router.post("/", response_model=TimelineEventResponse, status_code=status.HTTP_201_CREATED)
async def create_timeline_event(
    event_data: TimelineEventCreate,
    db: AsyncSession = Depends(get_db),
):
    """Manually add a timeline event"""
    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == event_data.case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    db_event = TimelineEvent(
        case_id=event_data.case_id,
        event_type=event_data.event_type,
        description=event_data.description,
        timestamp=event_data.timestamp,
        severity=event_data.severity,
        details=event_data.details,
        source_artifact_id=event_data.source_artifact_id,
    )

    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)

    return db_event


@router.get("/{event_id}", response_model=TimelineEventResponse)
async def get_timeline_event(event_id: int, db: AsyncSession = Depends(get_db)):
    """Get specific timeline event"""
    result = await db.execute(select(TimelineEvent).where(TimelineEvent.id == event_id))
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    return event


@router.put("/{event_id}", response_model=TimelineEventResponse)
async def update_timeline_event(
    event_id: int,
    event_data: TimelineEventCreate,
    db: AsyncSession = Depends(get_db),
):
    """Update a timeline event"""
    result = await db.execute(select(TimelineEvent).where(TimelineEvent.id == event_id))
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    update_data = event_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(event, field, value)

    await db.commit()
    await db.refresh(event)

    return event


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_timeline_event(event_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a timeline event"""
    result = await db.execute(select(TimelineEvent).where(TimelineEvent.id == event_id))
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    await db.delete(event)
    await db.commit()

    return None
