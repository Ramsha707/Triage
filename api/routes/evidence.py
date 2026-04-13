"""
Evidence Import API Routes
Handles upload and processing of forensic disk images
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
import os
import hashlib
import shutil
from dotenv import load_dotenv

from database.database import get_db
from database.models import Evidence, Case

load_dotenv()

router = APIRouter()

EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "./evidence")
MAX_FILE_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 10737418240))  # 10GB default

SUPPORTED_FORMATS = {
    ".raw": "RAW",
    ".img": "RAW",
    ".e01": "E01",
    ".aff": "AFF",
    ".vmdk": "VMDK",
    ".vdi": "VDI",
    ".qcow2": "QCOW2",
}


# Pydantic Schemas
class EvidenceResponse(BaseModel):
    id: int
    case_id: str
    name: str
    file_path: str
    file_type: str
    file_size: Optional[int]
    md5_hash: Optional[str]
    sha256_hash: Optional[str]
    is_processed: bool
    processing_status: str
    created_at: datetime

    class Config:
        from_attributes = True


class EvidenceUpdate(BaseModel):
    name: Optional[str] = None
    processing_status: Optional[str] = None
    is_processed: Optional[bool] = None


def calculate_hashes(file_path: str):
    """Calculate MD5 and SHA256 hashes of a file"""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()


@router.post("/upload", response_model=EvidenceResponse)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    description: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload forensic disk image evidence

    Supported formats: RAW, E01, AFF, VMDK, VDI, QCOW2
    """
    # Verify case exists
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    # Validate file extension
    ext = os.path.splitext(file.filename).lower()
    if ext not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format. Supported: {', '.join(SUPPORTED_FORMATS.keys())}"
        )

    # Create evidence directory for case
    case_evidence_dir = os.path.join(EVIDENCE_DIR, case_id)
    os.makedirs(case_evidence_dir, exist_ok=True)

    # Save file
    file_path = os.path.join(case_evidence_dir, file.filename)
    file_size = 0

    try:
        with open(file_path, "wb") as buffer:
            while chunk := await file.read(8192):
                file_size += len(chunk)
                buffer.write(chunk)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Upload failed: {str(e)}")

    # Calculate hashes
    md5, sha256 = calculate_hashes(file_path)

    # Create evidence record
    db_evidence = Evidence(
        case_id=case_id,
        name=file.filename,
        file_path=file_path,
        file_type=SUPPORTED_FORMATS[ext],
        file_size=file_size,
        md5_hash=md5,
        sha256_hash=sha256,
        processing_status="pending",
    )

    db.add(db_evidence)
    await db.commit()
    await db.refresh(db_evidence)

    # Trigger background processing (would use Celery/Redis in production)
    # For now, we'll process synchronously for small files
    # await process_evidence(db_evidence.id, db)

    return db_evidence


@router.get("/", response_model=List[EvidenceResponse])
async def get_evidence(case_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Get all evidence, optionally filtered by case"""
    query = select(Evidence)
    if case_id:
        query = query.where(Evidence.case_id == case_id)
    query = query.order_by(Evidence.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence_item(evidence_id: int, db: AsyncSession = Depends(get_db)):
    """Get specific evidence item"""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    return evidence


@router.post("/{evidence_id}/process")
async def process_evidence_endpoint(evidence_id: int, db: AsyncSession = Depends(get_db)):
    """
    Trigger evidence processing (artifact extraction)
    This would typically be handled by a background worker
    """
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    # Update status
    evidence.processing_status = "processing"
    await db.commit()

    # Import and run processor
    try:
        from services.evidence_processor import EvidenceProcessor
        processor = EvidenceProcessor()
        await processor.process(evidence, db)

        evidence.is_processed = True
        evidence.processing_status = "completed"
        await db.commit()

        return {"status": "completed", "message": "Evidence processed successfully"}
    except Exception as e:
        evidence.processing_status = "failed"
        await db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.put("/{evidence_id}", response_model=EvidenceResponse)
async def update_evidence(evidence_id: int, evidence_data: EvidenceUpdate, db: AsyncSession = Depends(get_db)):
    """Update evidence metadata"""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    update_data = evidence_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(evidence, field, value)

    await db.commit()
    await db.refresh(evidence)

    return evidence


@router.delete("/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_evidence(evidence_id: int, db: AsyncSession = Depends(get_db)):
    """Delete evidence"""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    # Delete file
    if os.path.exists(evidence.file_path):
        os.remove(evidence.file_path)

    await db.delete(evidence)
    await db.commit()

    return None
