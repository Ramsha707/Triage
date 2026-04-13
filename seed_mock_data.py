"""
Mock Data Seeder for Testing
Creates sample cases, evidence, artifacts, IOCs, and timeline events
"""
import asyncio
import random
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from sqlalchemy import select
from database.models import Base, Case, Evidence, Artifact, IOC, TimelineEvent, AnalysisResult, DetectionRule
from database.database import DATABASE_URL

# Create engine and session
engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def seed_detection_rules(db: AsyncSession):
    """Seed initial detection rules"""
    rules = [
        DetectionRule(
            name="Malicious IP Range",
            description="Detect connections to known malicious IP ranges",
            category="network",
            severity="critical",
            score=30,
            pattern=r"185\.220\.101\.\d+",
            enabled=True,
        ),
        DetectionRule(
            name="Suspicious Temp Executable",
            description="Executable files in temp directories",
            category="malware",
            severity="high",
            score=25,
            pattern=r"[/\\]Temp[/\\].*\.exe$",
            enabled=True,
        ),
        DetectionRule(
            name="Registry Persistence",
            description="Autorun registry modifications",
            category="persistence",
            severity="high",
            score=25,
            pattern=r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            enabled=True,
        ),
        DetectionRule(
            name="PowerShell Encoded Command",
            description="Base64 encoded PowerShell commands",
            category="privilege_escalation",
            severity="high",
            score=20,
            pattern=r"-EncodedCommand|-Enc ",
            enabled=True,
        ),
        DetectionRule(
            name="Hidden System File",
            description="Hidden files in system directories",
            category="malware",
            severity="medium",
            score=15,
            pattern=r"[/\\]System32[/\\]\..*$",
            enabled=True,
        ),
    ]

    for rule in rules:
        existing = await db.execute(
            select(DetectionRule).where(DetectionRule.name == rule.name)
        )
        if not existing.scalar_one_or_none():
            db.add(rule)

    await db.commit()
    print("[OK] Seeded detection rules")


async def seed_mock_cases(db: AsyncSession):
    """Create mock investigation cases"""

    # Case 1: Malware Investigation
    case1 = Case(
        case_id="CTF-2025-001",
        title="Workstation Malware Infection",
        description="Suspected ransomware infection on finance department workstation",
        investigator="Arfat Shaikh",
        status="active",
        risk_score=82.5,
        risk_level="critical",
    )
    db.add(case1)
    await db.commit()

    # Create evidence for case 1
    evidence1 = Evidence(
        case_id="CTF-2025-001",
        name="workstation_disk.raw",
        file_path="./evidence/CTF-2025-001/workstation_disk.raw",
        file_type="RAW",
        file_size=53687091200,  # 50GB
        md5_hash="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        sha256_hash="1234567890abcdef" * 8,
        is_processed=True,
        processing_status="completed",
    )
    db.add(evidence1)
    await db.commit()

    # Create artifacts for case 1
    artifacts = [
        Artifact(
            case_id="CTF-2025-001",
            artifact_type="file",
            name="ransomware.exe",
            path="C:/Users/Finance/Downloads",
            file_type="file",
            size=2456789,
            md5_hash="d41d8cd98f00b204e9800998ecf8427e",
            deleted=False,
            hidden=False,
            risk_score=95,
            tags=["malware", "ransomware", "suspicious"],
            created_time=datetime.now() - timedelta(hours=48),
            modified_time=datetime.now() - timedelta(hours=47),
        ),
        Artifact(
            case_id="CTF-2025-001",
            artifact_type="file",
            name="keylog_output.log",
            path="C:/Windows/Temp",
            file_type="file",
            size=45678,
            deleted=True,
            hidden=True,
            risk_score=85,
            tags=["keylogger", "suspicious"],
            created_time=datetime.now() - timedelta(hours=72),
            modified_time=datetime.now() - timedelta(hours=24),
        ),
        Artifact(
            case_id="CTF-2025-001",
            artifact_type="registry",
            name="Microsoft\\Windows\\CurrentVersion\\Run\\svchost",
            path="HKLM\\Software",
            file_type="registry",
            size=256,
            deleted=False,
            hidden=False,
            risk_score=90,
            tags=["persistence", "autorun"],
            created_time=datetime.now() - timedelta(hours=48),
        ),
        Artifact(
            case_id="CTF-2025-001",
            artifact_type="network",
            name="Connection to 185.220.101.45:443",
            path="outbound",
            file_type="network",
            size=0,
            deleted=False,
            hidden=False,
            risk_score=88,
            tags=["c2", "malicious_ip"],
            created_time=datetime.now() - timedelta(hours=46),
        ),
        Artifact(
            case_id="CTF-2025-001",
            artifact_type="browser_history",
            name="darkweb_access.log",
            path="C:/Users/Finance/AppData/Local/Tor",
            file_type="browser_history",
            size=12345,
            deleted=False,
            hidden=True,
            risk_score=75,
            tags=["tor", "suspicious"],
            created_time=datetime.now() - timedelta(hours=12),
        ),
        Artifact(
            case_id="CTF-2025-001",
            artifact_type="file",
            name="stolen_data.zip",
            path="C:/Users/Finance/Documents",
            file_type="archive",
            size=9876543,
            deleted=False,
            hidden=False,
            risk_score=70,
            tags=["exfiltration", "suspicious"],
            created_time=datetime.now() - timedelta(hours=6),
        ),
    ]

    for artifact in artifacts:
        db.add(artifact)

    # Create IOCs for case 1
    iocs = [
        IOC(
            case_id="CTF-2025-001",
            ioc_type="ip",
            value="185.220.101.45",
            source="network_connection",
            confidence=95,
            severity="critical",
            description="Known malicious IP - C2 server",
            is_malicious=True,
            rule_matched="malicious_ip",
        ),
        IOC(
            case_id="CTF-2025-001",
            ioc_type="hash",
            value="d41d8cd98f00b204e9800998ecf8427e",
            source="ransomware.exe",
            confidence=90,
            severity="critical",
            description="Known ransomware hash",
            is_malicious=True,
            rule_matched="malicious_hash",
        ),
        IOC(
            case_id="CTF-2025-001",
            ioc_type="registry_key",
            value="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost",
            source="registry_artifact",
            confidence=85,
            severity="high",
            description="Persistence mechanism detected",
            is_malicious=True,
            rule_matched="registry_persistence",
        ),
        IOC(
            case_id="CTF-2025-001",
            ioc_type="file_path",
            value="C:/Windows/Temp/keylog_output.log",
            source="file_artifact",
            confidence=80,
            severity="high",
            description="Keylogger output in temp directory",
            is_malicious=False,
            rule_matched="suspicious_file_path",
        ),
    ]

    for ioc in iocs:
        db.add(ioc)

    # Create timeline events for case 1
    base_time = datetime.now() - timedelta(hours=72)
    timeline_events = [
        TimelineEvent(
            case_id="CTF-2025-001",
            timestamp=base_time,
            event_type="file_created",
            description="Malicious file created: keylog_output.log",
            severity="warning",
            details={"file": "keylog_output.log"},
        ),
        TimelineEvent(
            case_id="CTF-2025-001",
            timestamp=base_time + timedelta(hours=24),
            event_type="file_created",
            description="Ransomware executed: ransomware.exe",
            severity="critical",
            details={"file": "ransomware.exe"},
        ),
        TimelineEvent(
            case_id="CTF-2025-001",
            timestamp=base_time + timedelta(hours=26),
            event_type="registry_change",
            description="Persistence mechanism installed via registry",
            severity="critical",
            details={"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ),
        TimelineEvent(
            case_id="CTF-2025-001",
            timestamp=base_time + timedelta(hours=28),
            event_type="network_connection",
            description="C2 communication detected to 185.220.101.45",
            severity="critical",
            details={"ip": "185.220.101.45", "port": 443},
        ),
        TimelineEvent(
            case_id="CTF-2025-001",
            timestamp=base_time + timedelta(hours=66),
            event_type="file_created",
            description="Data exfiltration package created: stolen_data.zip",
            severity="high",
            details={"file": "stolen_data.zip"},
        ),
        TimelineEvent(
            case_id="CTF-2025-001",
            timestamp=base_time + timedelta(hours=70),
            event_type="web_access",
            description="Tor browser activity detected",
            severity="high",
            details={"browser": "Tor"},
        ),
    ]

    for event in timeline_events:
        db.add(event)

    # Create analysis results for case 1
    analysis = AnalysisResult(
        case_id="CTF-2025-001",
        analysis_type="risk_prediction",
        model_name="RiskModel",
        model_version="1.0.0",
        results={
            "overall_risk_score": 82.5,
            "risk_level": "critical",
            "artifact_risk": {"score": 75, "suspicious_count": 4},
            "ioc_risk": {"score": 90, "malicious_count": 3},
            "behavioral_risk": {"score": 70, "critical_events": 3},
        },
        confidence_score=85,
        anomalies_detected=6,
        recommendations=[
            "Isolate affected system immediately",
            "Analyze ransomware.exe in sandbox environment",
            "Check for lateral movement to other systems",
            "Preserve evidence for forensic analysis",
        ],
    )
    db.add(analysis)

    await db.commit()
    print("[OK] Seeded case CTF-2025-001 (Malware Investigation)")

    # Case 2: Insider Threat
    case2 = Case(
        case_id="CTF-2025-002",
        title="Insider Data Theft Investigation",
        description="Suspected data exfiltration by departing employee",
        investigator="Security Team",
        status="active",
        risk_score=45,
        risk_level="medium",
    )
    db.add(case2)
    await db.commit()

    # Evidence for case 2
    evidence2 = Evidence(
        case_id="CTF-2025-002",
        name="usb_device.raw",
        file_path="./evidence/CTF-2025-002/usb_device.raw",
        file_type="RAW",
        file_size=8589934592,  # 8GB
        is_processed=True,
        processing_status="completed",
    )
    db.add(evidence2)
    await db.commit()

    # Artifacts for case 2
    artifacts2 = [
        Artifact(
            case_id="CTF-2025-002",
            artifact_type="file",
            name="confidential_reports.zip",
            path="E:/",
            file_type="archive",
            size=52428800,
            deleted=False,
            hidden=False,
            risk_score=60,
            tags=["exfiltration", "usb"],
            created_time=datetime.now() - timedelta(days=2),
        ),
        Artifact(
            case_id="CTF-2025-002",
            artifact_type="file",
            name="employee_resignation.pdf",
            path="C:/Users/Employee/Documents",
            file_type="file",
            size=245000,
            deleted=False,
            hidden=False,
            risk_score=30,
            tags=[],
            created_time=datetime.now() - timedelta(days=5),
        ),
    ]

    for artifact in artifacts2:
        db.add(artifact)

    await db.commit()
    print("[OK] Seeded case CTF-2025-002 (Insider Threat)")

    print("\n[OK] Mock data seeding complete!")
    print("\nAvailable cases:")
    print("  - CTF-2025-001: Workstation Malware Infection (Critical Risk)")
    print("  - CTF-2025-002: Insider Data Theft Investigation (Medium Risk)")


async def main():
    """Main seeding function"""
    print("=" * 50)
    print("  Cyber Triage Tool - Mock Data Seeder")
    print("=" * 50)
    print()

    async with AsyncSessionLocal() as db:
        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Seed data
        await seed_detection_rules(db)
        await seed_mock_cases(db)


if __name__ == "__main__":
    asyncio.run(main())
