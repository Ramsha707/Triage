"""
Database Models for Cyber Triage Tool
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class Case(Base):
    """Case management - tracks individual investigations"""
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g., CTF-2025-001
    title = Column(String(255), nullable=False)
    description = Column(Text)
    investigator = Column(String(100), nullable=False)
    status = Column(String(20), default="active")  # active, closed, archived
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="low")  # low, medium, high, critical

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    artifacts = relationship("Artifact", back_populates="case", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResult", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    """Evidence items - disk images, files, etc."""
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    name = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_type = Column(String(50))  # RAW, E01, AFF, VMDK
    file_size = Column(Integer)
    md5_hash = Column(String(64))
    sha256_hash = Column(String(128))
    acquisition_date = Column(DateTime)
    acquisition_tool = Column(String(100))
    chain_of_custody = Column(JSON, default=list)
    is_processed = Column(Boolean, default=False)
    processing_status = Column(String(20), default="pending")  # pending, processing, completed, failed

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="evidence_items")


class Artifact(Base):
    """Extracted artifacts from evidence"""
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    artifact_type = Column(String(50), nullable=False)  # file, registry, network, browser_history, event_log
    name = Column(String(255), nullable=False)
    path = Column(String(512))
    file_type = Column(String(50))
    size = Column(Integer)
    md5_hash = Column(String(64))
    sha256_hash = Column(String(128))
    created_time = Column(DateTime)
    modified_time = Column(DateTime)
    accessed_time = Column(DateTime)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    artifact_metadata = Column(JSON, default=dict)
    risk_score = Column(Float, default=0.0)
    tags = Column(JSON, default=list)  # e.g., ["suspicious", "malware", "autorun"]

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="artifacts")


class IOC(Base):
    """Indicators of Compromise"""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    ioc_type = Column(String(50), nullable=False)  # hash, ip, domain, url, file_path, registry_key, mutex
    value = Column(String(512), nullable=False)
    source = Column(String(100))  # Where was this found
    confidence = Column(Float, default=0.0)  # 0-100
    severity = Column(String(20))  # low, medium, high, critical
    description = Column(Text)
    virustotal_results = Column(JSON, default=dict)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    is_malicious = Column(Boolean, default=False)
    rule_matched = Column(String(100))  # Which detection rule matched

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="iocs")


class TimelineEvent(Base):
    """Chronological timeline events"""
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # file_created, file_modified, file_deleted, registry_change, network_connection, process_execution, user_login
    description = Column(Text, nullable=False)
    source_artifact_id = Column(Integer, ForeignKey("artifacts.id"))
    severity = Column(String(20), default="info")  # info, warning, high, critical
    details = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="timeline_events")


class AnalysisResult(Base):
    """AI/ML analysis results"""
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    analysis_type = Column(String(50), nullable=False)  # anomaly_detection, risk_prediction, behavioral_analysis, clustering
    model_name = Column(String(100))
    model_version = Column(String(20))
    results = Column(JSON, nullable=False)
    confidence_score = Column(Float)
    anomalies_detected = Column(Integer, default=0)
    recommendations = Column(JSON, default=list)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="analysis_results")


class DetectionRule(Base):
    """YARA-like detection rules"""
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    category = Column(String(50))  # malware, persistence, exfiltration, privilege_escalation
    severity = Column(String(20), default="medium")
    score = Column(Integer, default=0)  # Points added when rule matches
    pattern = Column(Text, nullable=False)  # Regex or pattern to match
    enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Report(Base):
    """Generated reports"""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    report_type = Column(String(20), nullable=False)  # pdf, json, csv
    file_path = Column(String(512), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer)
    generated_by = Column(String(100))
    includes = Column(JSON, default=list)  # What's included: [artifacts, iocs, timeline, analysis]

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="reports")


class User(Base):
    """User accounts for role-based access"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    role = Column(String(20), default="analyst")  # admin, investigator, analyst, viewer
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)
