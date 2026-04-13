"""
Evidence Processor Service
Handles parsing and processing of forensic disk images
"""
import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import asyncio

# Try to import pytsk3, fall back to mock if not available
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    print("Warning: pytsk3 not available. Using mock processing.")


class EvidenceProcessor:
    """Process forensic disk images and extract metadata"""

    def __init__(self):
        self.supported_formats = ["RAW", "E01", "AFF", "VMDK"]

    async def process(self, evidence, db) -> Dict[str, Any]:
        """
        Process evidence file

        Args:
            evidence: Evidence database model instance
            db: Database session

        Returns:
            Processing results dictionary
        """
        if not os.path.exists(evidence.file_path):
            raise FileNotFoundError(f"Evidence file not found: {evidence.file_path}")

        # Update status
        evidence.processing_status = "processing"
        await db.commit()

        try:
            if TSK_AVAILABLE:
                results = await self._process_with_tsk(evidence, db)
            else:
                results = await self._mock_process(evidence, db)

            evidence.is_processed = True
            evidence.processing_status = "completed"
            await db.commit()

            return results

        except Exception as e:
            evidence.processing_status = "failed"
            await db.commit()
            raise e

    async def _process_with_tsk(self, evidence, db) -> Dict[str, Any]:
        """Process using The Sleuth Kit (pytsk3)"""
        from database.models import Artifact, TimelineEvent

        results = {
            "files_found": 0,
            "deleted_files": 0,
            "total_size": 0,
            "artifacts_created": 0,
        }

        # Open image using pytsk3
        img_info = pytsk3.Image_Info(evidence.file_path)
        vs = pytsk3.Volume_Info(img_info)

        # Iterate through partitions
        for partition in vs:
            if not hasattr(partition, "addr"):
                continue

            try:
                fs = pytsk3.FS_Info(img_info, offset=partition.addr * 512)
            except Exception:
                continue

            # Walk the file system
            for file_entry in fs.walk():
                try:
                    name = file_entry.info.name.name.decode("utf-8", errors="ignore")
                    if name in [".", ".."]:
                        continue

                    path = file_entry.info.info.name.decode("utf-8", errors="ignore") if hasattr(file_entry.info, "info") else ""

                    # Get file metadata
                    file_type = "file"
                    if file_entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        file_type = "directory"

                    is_deleted = file_entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC
                    is_hidden = name.startswith(".")

                    # Create artifact record
                    artifact = Artifact(
                        case_id=evidence.case_id,
                        artifact_type="file",
                        name=name,
                        path=path,
                        file_type=file_type,
                        size=file_entry.info.meta.size if hasattr(file_entry.info.meta, "size") else 0,
                        deleted=bool(is_deleted),
                        hidden=is_hidden,
                        artifact_metadata={
                            "inode": file_entry.info.meta.addr if hasattr(file_entry.info.meta, "addr") else None,
                        },
                    )

                    db.add(artifact)
                    results["files_found"] += 1

                    if is_deleted:
                        results["deleted_files"] += 1

                    results["total_size"] += artifact.size or 0

                    # Create timeline event for file creation
                    if hasattr(file_entry.info.meta, "crtime"):
                        crtime = file_entry.info.meta.crtime
                        if crtime > 0:
                            timeline_event = TimelineEvent(
                                case_id=evidence.case_id,
                                timestamp=datetime.fromtimestamp(crtime),
                                event_type="file_created",
                                description=f"File created: {name}",
                                severity="info",
                                details={"path": path},
                            )
                            db.add(timeline_event)

                except Exception as e:
                    continue

        await db.commit()
        results["artifacts_created"] = len(db.new)

        return results

    async def _mock_process(self, evidence, db) -> Dict[str, Any]:
        """
        Mock processing for demonstration when pytsk3 is not available
        Simulates artifact extraction
        """
        from database.models import Artifact, TimelineEvent
        import random

        results = {
            "files_found": 0,
            "deleted_files": 0,
            "total_size": 0,
            "artifacts_created": 0,
        }

        # Simulated artifacts for demo purposes
        mock_artifacts = [
            {"name": "chrome_history.db", "path": "/Users/Admin/AppData/Local/Google/Chrome", "type": "browser_history", "size": 2456789, "deleted": False},
            {"name": "malware.exe", "path": "/Users/Admin/Downloads", "type": "file", "size": 1234567, "deleted": False, "suspicious": True},
            {"name": "keylog_output.log", "path": "/Users/Admin/AppData/Local/Temp", "type": "file", "size": 45678, "deleted": True, "suspicious": True},
            {"name": "stolen_data.zip", "path": "/Users/Admin/Documents", "type": "file", "size": 9876543, "deleted": False, "suspicious": True},
            {"name": ".hidden_config", "path": "/Users/Admin", "type": "file", "size": 1234, "deleted": False, "hidden": True},
            {"name": "autorun.inf", "path": "/C:/Windows/System32", "type": "registry", "size": 512, "deleted": False, "suspicious": True},
            {"name": "connection.log", "path": "/var/log", "type": "network", "size": 34567, "deleted": False},
            {"name": "deleted_document.docx", "path": "/Users/Admin/Documents", "type": "file", "size": 567890, "deleted": True},
            {"name": "firefox_cookies.sqlite", "path": "/Users/Admin/AppData/Roaming/Mozilla/Firefox", "type": "browser_history", "size": 234567, "deleted": False},
            {"name": "suspicious.dll", "path": "/C:/Windows/Temp", "type": "file", "size": 876543, "deleted": False, "suspicious": True},
        ]

        base_time = datetime.now()

        for i, mock in enumerate(mock_artifacts):
            artifact = Artifact(
                case_id=evidence.case_id,
                artifact_type=mock.get("type", "file"),
                name=mock["name"],
                path=mock.get("path", "/unknown"),
                file_type=mock.get("type", "file"),
                size=mock.get("size", 0),
                deleted=mock.get("deleted", False),
                hidden=mock.get("hidden", False),
                risk_score=80 if mock.get("suspicious") else 10,
                tags=["suspicious"] if mock.get("suspicious") else [],
                artifact_metadata={"source_evidence": evidence.id},
                created_time=base_time - timedelta(hours=i),
                modified_time=base_time - timedelta(hours=i-1),
            )

            db.add(artifact)
            results["files_found"] += 1

            if artifact.deleted:
                results["deleted_files"] += 1

            results["total_size"] += artifact.size or 0

            # Create timeline event
            if artifact.created_time:
                event = TimelineEvent(
                    case_id=evidence.case_id,
                    timestamp=artifact.created_time,
                    event_type="file_created" if not artifact.deleted else "file_deleted",
                    description=f"{'Deleted' if artifact.deleted else 'Created'}: {mock['name']}",
                    severity="warning" if mock.get("suspicious") else "info",
                    details={"path": mock.get("path")},
                )
                db.add(event)

        await db.commit()
        results["artifacts_created"] = len(mock_artifacts)

        return results

    def calculate_file_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """Calculate hash of a file"""
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()
