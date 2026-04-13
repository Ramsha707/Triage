"""
Timeline Generator Service
Creates chronological event timelines from artifacts
"""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import TimelineEvent, Artifact, Case


class TimelineGenerator:
    """Generate timeline events from forensic artifacts"""

    # Event type mappings
    ARTIFACT_TO_EVENT_TYPE = {
        "file": "file_created",
        "registry": "registry_change",
        "network": "network_connection",
        "browser_history": "web_access",
        "event_log": "system_event",
    }

    SEVERITY_KEYWORDS = {
        "critical": ["malware", "exploit", "backdoor", "rootkit", "ransomware"],
        "high": ["suspicious", "unauthorized", "deleted", "hidden", "persistence"],
        "warning": ["temp", "download", "external", "usb", "removable"],
    }

    def __init__(self):
        pass

    async def generate(self, request, db: AsyncSession) -> List[Dict[str, Any]]:
        """
        Generate timeline from case artifacts

        Args:
            request: TimelineGenerateRequest
            db: Database session

        Returns:
            List of generated timeline events
        """
        # Get all artifacts for the case
        query = select(Artifact).where(Artifact.case_id == request.case_id)

        if request.start_time:
            # Filter by time range on created_time
            pass  # Will filter after fetching

        if request.event_types:
            # Filter by artifact type
            type_mapping = {
                "file_created": "file",
                "registry_change": "registry",
                "network_connection": "network",
                "web_access": "browser_history",
            }
            artifact_types = [type_mapping.get(et, "file") for et in request.event_types]
            query = query.where(Artifact.artifact_type.in_(artifact_types))

        result = await db.execute(query)
        artifacts = result.scalars().all()

        events = []

        for artifact in artifacts:
            # Generate events from artifact timestamps
            artifact_events = await self._generate_events_for_artifact(artifact, request, db)
            events.extend(artifact_events)

        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", datetime.min))

        return events

    async def _generate_events_for_artifact(
        self,
        artifact: Artifact,
        request,
        db: AsyncSession,
    ) -> List[Dict[str, Any]]:
        """Generate timeline events from a single artifact"""
        events = []

        # Determine event type
        event_type = self.ARTIFACT_TO_EVENT_TYPE.get(artifact.artifact_type, "file_created")

        # Determine severity
        severity = self._determine_severity(artifact)

        # Generate creation event
        if artifact.created_time:
            creation_event = TimelineEvent(
                case_id=artifact.case_id,
                timestamp=artifact.created_time,
                event_type=event_type,
                description=self._generate_description(artifact, "created"),
                severity=severity,
                details={
                    "artifact_id": artifact.id,
                    "name": artifact.name,
                    "path": artifact.path,
                    "size": artifact.size,
                    "hash": artifact.md5_hash,
                },
                source_artifact_id=artifact.id,
            )
            db.add(creation_event)
            events.append(self._event_to_dict(creation_event))

        # Generate modification event
        if artifact.modified_time and artifact.modified_time != artifact.created_time:
            mod_event = TimelineEvent(
                case_id=artifact.case_id,
                timestamp=artifact.modified_time,
                event_type="file_modified" if artifact.artifact_type == "file" else event_type,
                description=self._generate_description(artifact, "modified"),
                severity=severity,
                details={
                    "artifact_id": artifact.id,
                    "name": artifact.name,
                    "path": artifact.path,
                },
                source_artifact_id=artifact.id,
            )
            db.add(mod_event)
            events.append(self._event_to_dict(mod_event))

        # Generate deletion event if marked as deleted
        if artifact.deleted and artifact.accessed_time:
            delete_event = TimelineEvent(
                case_id=artifact.case_id,
                timestamp=artifact.accessed_time,
                event_type="file_deleted",
                description=self._generate_description(artifact, "deleted"),
                severity="high" if severity in ["critical", "high"] else "warning",
                details={
                    "artifact_id": artifact.id,
                    "name": artifact.name,
                    "path": artifact.path,
                    "recovery_possible": True,
                },
                source_artifact_id=artifact.id,
            )
            db.add(delete_event)
            events.append(self._event_to_dict(delete_event))

        await db.commit()

        return events

    def _determine_severity(self, artifact: Artifact) -> str:
        """Determine event severity based on artifact characteristics"""
        # Check for critical indicators
        if artifact.risk_score and artifact.risk_score >= 80:
            return "critical"

        if artifact.tags:
            if any(tag in ["malware", "malicious", "exploit"] for tag in artifact.tags):
                return "critical"
            if any(tag in ["suspicious", "autorun", "persistence"] for tag in artifact.tags):
                return "high"

        if artifact.deleted:
            return "warning"

        if artifact.hidden:
            return "warning"

        # Check name/path for suspicious keywords
        text_to_check = f"{artifact.name} {artifact.path}".lower()

        for severity, keywords in self.SEVERITY_KEYWORDS.items():
            if any(keyword in text_to_check for keyword in keywords):
                return severity

        return "info"

    def _generate_description(self, artifact: Artifact, action: str) -> str:
        """Generate human-readable event description"""
        descriptions = {
            "created": f"File {action}: {artifact.name}",
            "modified": f"File {action}: {artifact.name}",
            "deleted": f"File {action}: {artifact.name}",
        }

        if artifact.artifact_type == "registry":
            descriptions = {
                "created": f"Registry key created/modified: {artifact.name}",
                "modified": f"Registry key modified: {artifact.name}",
                "deleted": f"Registry key deleted: {artifact.name}",
            }
        elif artifact.artifact_type == "network":
            descriptions = {
                "created": f"Network connection: {artifact.name}",
                "modified": f"Network activity: {artifact.name}",
                "deleted": f"Network connection closed: {artifact.name}",
            }
        elif artifact.artifact_type == "browser_history":
            descriptions = {
                "created": f"Web access: {artifact.name}",
                "modified": f"Web activity: {artifact.name}",
                "deleted": f"Browser history cleared: {artifact.name}",
            }

        return descriptions.get(action, f"Event: {artifact.name}")

    def _event_to_dict(self, event: TimelineEvent) -> Dict[str, Any]:
        """Convert TimelineEvent to dictionary"""
        return {
            "id": event.id,
            "case_id": event.case_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "event_type": event.event_type,
            "description": event.description,
            "severity": event.severity,
            "details": event.details,
        }

    async def generate_from_evidence(self, evidence, db: AsyncSession) -> List[TimelineEvent]:
        """Generate timeline directly from evidence file"""
        events = []

        # This would integrate with the evidence processor
        # For now, we generate from already-extracted artifacts
        pass

        return events

    async def correlate_events(self, case_id: str, db: AsyncSession) -> Dict[str, Any]:
        """
        Correlate timeline events to identify related activities

        Returns:
            Correlation analysis results
        """
        query = select(TimelineEvent).where(TimelineEvent.case_id == case_id)
        result = await db.execute(query)
        events = result.scalars().all()

        correlations = {
            "sequences": [],
            "clusters": [],
            "gaps": [],
        }

        # Find event sequences (events within 5 minutes of each other)
        if len(events) > 1:
            events_sorted = sorted(events, key=lambda e: e.timestamp or datetime.min)

            current_sequence = [events_sorted[0]]
            for i in range(1, len(events_sorted)):
                time_diff = (events_sorted[i].timestamp - events_sorted[i-1].timestamp).total_seconds()
                if time_diff <= 300:  # 5 minutes
                    current_sequence.append(events_sorted[i])
                else:
                    if len(current_sequence) >= 3:
                        correlations["sequences"].append({
                            "events": [e.id for e in current_sequence],
                            "duration_seconds": (current_sequence[-1].timestamp - current_sequence[0].timestamp).total_seconds(),
                            "event_count": len(current_sequence),
                        })
                    current_sequence = [events_sorted[i]]

        # Find event clusters by type
        event_types = {}
        for event in events:
            if event.event_type not in event_types:
                event_types[event.event_type] = []
            event_types[event.event_type].append(event.id)

        for event_type, ids in event_types.items():
            if len(ids) >= 3:
                correlations["clusters"].append({
                    "type": event_type,
                    "event_ids": ids,
                    "count": len(ids),
                })

        return correlations
