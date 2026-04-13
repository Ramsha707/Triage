"""
Artifact Explorer API Routes
Extracted artifacts from forensic evidence
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from database.database import get_db
from database.models import Artifact, Case

router = APIRouter()


# Pydantic Schemas
class ArtifactResponse(BaseModel):
    id: int
    case_id: str
    artifact_type: str
    name: str
    path: Optional[str]
    file_type: Optional[str]
    size: Optional[int]
    md5_hash: Optional[str]
    sha256_hash: Optional[str]
    created_time: Optional[datetime]
    modified_time: Optional[datetime]
    accessed_time: Optional[datetime]
    deleted: bool
    hidden: bool
    artifact_metadata: dict
    risk_score: float
    tags: list

    class Config:
        from_attributes = True


class ArtifactFilter(BaseModel):
    artifact_type: Optional[str] = None
    deleted: Optional[bool] = None
    hidden: Optional[bool] = None
    risk_score_min: Optional[float] = None
    tags: Optional[List[str]] = None


@router.get("/", response_model=List[ArtifactResponse])
async def get_artifacts(
    case_id: str = Query(...),
    artifact_type: Optional[str] = Query(None),
    deleted: Optional[bool] = Query(None),
    hidden: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    Get artifacts from a case with optional filtering

    - **case_id**: Case to fetch artifacts from
    - **artifact_type**: Filter by type (file, registry, network, browser_history, event_log)
    - **deleted**: Filter by deletion status
    - **hidden**: Filter by hidden attribute
    - **search**: Search in name/path
    """
    query = select(Artifact).where(Artifact.case_id == case_id)

    if artifact_type:
        query = query.where(Artifact.artifact_type == artifact_type)
    if deleted is not None:
        query = query.where(Artifact.deleted == deleted)
    if hidden is not None:
        query = query.where(Artifact.hidden == hidden)
    if search:
        query = query.where(
            (Artifact.name.ilike(f"%{search}%")) |
            (Artifact.path.ilike(f"%{search}%"))
        )

    query = query.order_by(Artifact.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/types")
async def get_artifact_types(db: AsyncSession = Depends(get_db)):
    """Get available artifact types and counts"""
    query = select(Artifact.artifact_type, func.count(Artifact.id)).group_by(Artifact.artifact_type)
    result = await db.execute(query)

    return [
        {"type": row[0], "count": row[1]}
        for row in result.all()
    ]


@router.get("/stats")
async def get_artifact_stats(case_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    """Get artifact statistics for a case"""
    total = (await db.execute(select(func.count(Artifact.id)).where(Artifact.case_id == case_id))).scalar()
    deleted_count = (await db.execute(select(func.count(Artifact.id)).where(
        Artifact.case_id == case_id, Artifact.deleted == True
    ))).scalar()
    hidden_count = (await db.execute(select(func.count(Artifact.id)).where(
        Artifact.case_id == case_id, Artifact.hidden == True
    ))).scalar()
    high_risk = (await db.execute(select(func.count(Artifact.id)).where(
        Artifact.case_id == case_id, Artifact.risk_score >= 50
    ))).scalar()

    # By type
    type_query = select(Artifact.artifact_type, func.count(Artifact.id)).where(
        Artifact.case_id == case_id
    ).group_by(Artifact.artifact_type)
    type_result = await db.execute(type_query)
    by_type = {row[0]: row[1] for row in type_result.all()}

    return {
        "total": total or 0,
        "deleted": deleted_count or 0,
        "hidden": hidden_count or 0,
        "high_risk": high_risk or 0,
        "by_type": by_type,
    }


@router.get("/{artifact_id}", response_model=ArtifactResponse)
async def get_artifact(artifact_id: int, db: AsyncSession = Depends(get_db)):
    """Get specific artifact by ID"""
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    return artifact


@router.post("/{artifact_id}/tag")
async def add_artifact_tag(
    artifact_id: int,
    tag: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Add a tag to an artifact"""
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    if tag not in artifact.tags:
        artifact.tags.append(tag)
        await db.commit()

    return {"id": artifact.id, "tags": artifact.tags}


@router.delete("/{artifact_id}/tag/{tag}")
async def remove_artifact_tag(
    artifact_id: int,
    tag: str,
    db: AsyncSession = Depends(get_db),
):
    """Remove a tag from an artifact"""
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    if tag in artifact.tags:
        artifact.tags.remove(tag)
        await db.commit()

    return {"id": artifact.id, "tags": artifact.tags}


@router.delete("/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_artifact(artifact_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an artifact"""
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    await db.delete(artifact)
    await db.commit()

    return None
