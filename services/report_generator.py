"""
Report Generator Service
Generate forensic reports in PDF, JSON, and CSV formats
"""
import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import Case, Evidence, Artifact, IOC, TimelineEvent, AnalysisResult, Report

# Try to import reportlab for PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: reportlab not available. PDF generation disabled.")


class ReportGenerator:
    """Generate forensic reports in multiple formats"""

    def __init__(self):
        self.reports_dir = os.getenv("REPORTS_DIR", "./reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    async def generate(self, request, db: AsyncSession) -> Dict[str, Any]:
        """
        Generate a report in the specified format

        Args:
            request: ReportGenerateRequest
            db: Database session

        Returns:
            Dictionary with file_path, file_name, file_size
        """
        # Get case data
        case = await self._get_case(request.case_id, db)
        if not case:
            raise ValueError(f"Case not found: {request.case_id}")

        # Get related data
        evidence = await self._get_evidence(request.case_id, db) if request.include_artifacts else []
        artifacts = await self._get_artifacts(request.case_id, db) if request.include_artifacts else []
        iocs = await self._get_iocs(request.case_id, db) if request.include_iocs else []
        timeline = await self._get_timeline(request.case_id, db) if request.include_timeline else []
        analysis = await self._get_analysis(request.case_id, db) if request.include_analysis else []

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{case.case_id}_report_{timestamp}"

        # Generate report based on format
        if request.report_type == "pdf":
            if not REPORTLAB_AVAILABLE:
                # Fallback to JSON if PDF not available
                request.report_type = "json"
            else:
                file_path = await self._generate_pdf(
                    base_filename, case, evidence, artifacts, iocs, timeline, analysis
                )
        elif request.report_type == "json":
            file_path = await self._generate_json(
                base_filename, case, evidence, artifacts, iocs, timeline, analysis
            )
        elif request.report_type == "csv":
            file_path = await self._generate_csv(
                base_filename, artifacts, iocs, timeline
            )
        else:
            raise ValueError(f"Unsupported report type: {request.report_type}")

        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
        }

    async def _generate_pdf(
        self,
        filename: str,
        case: Case,
        evidence: List,
        artifacts: List,
        iocs: List,
        timeline: List,
        analysis: List,
    ) -> str:
        """Generate PDF report"""
        file_path = os.path.join(self.reports_dir, f"{filename}.pdf")
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00ffe5'),
            spaceAfter=30,
            alignment=TA_CENTER,
        )
        elements.append(Paragraph("CYBER TRIAGE FORENSIC REPORT", title_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Case Info
        case_info = [
            ["Case ID:", case.case_id],
            ["Title:", case.title],
            ["Investigator:", case.investigator],
            ["Risk Level:", case.risk_level.upper()],
            ["Risk Score:", f"{case.risk_score:.1f}/100"],
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ]
        case_table = Table(case_info, colWidths=[2*inch, 4*inch])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00ffe5')),
        ]))
        elements.append(case_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", styles['Heading2']))
        elements.append(Spacer(1, 0.1 * inch))
        summary_text = f"""
        This forensic analysis report documents the investigation of case {case.case_id}.
        A total of {len(artifacts)} artifacts were analyzed, with {len(iocs)} indicators of compromise identified.
        The overall risk assessment is <b>{case.risk_level.upper()}</b> with a score of {case.risk_score:.1f}/100.
        """
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 0.3 * inch))

        # Evidence Section
        if evidence:
            elements.append(Paragraph("EVIDENCE ITEMS", styles['Heading2']))
            evidence_data = [["Name", "Type", "Size (MB)", "Hash (MD5)"]]
            for e in evidence[:10]:  # Limit to 10
                evidence_data.append([
                    e.name[:30],
                    e.file_type,
                    f"{(e.file_size or 0) / 1024 / 1024:.2f}",
                    (e.md5_hash or "N/A")[:16] + "..." if e.md5_hash else "N/A",
                ])
            evidence_table = Table(evidence_data, colWidths=[2, 1, 1, 2.5])
            evidence_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00ffe5')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(evidence_table)
            elements.append(Spacer(1, 0.3 * inch))

        # IOCs Section
        if iocs:
            elements.append(Paragraph("INDICATORS OF COMPROMISE", styles['Heading2']))
            ioc_data = [["Type", "Value", "Severity", "Confidence"]]
            for ioc in iocs[:20]:  # Limit to 20
                severity_color = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "yellow",
                    "low": "green",
                }.get(ioc.severity, "black")
                ioc_data.append([
                    ioc.ioc_type,
                    ioc.value[:40],
                    ioc.severity.upper(),
                    f"{ioc.confidence:.0f}%",
                ])
            ioc_table = Table(ioc_data, colWidths=[1.5, 3, 1.5, 1.5])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ff3a3a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(ioc_table)
            elements.append(Spacer(1, 0.3 * inch))

        # Recommendations
        if analysis:
            elements.append(Paragraph("RECOMMENDATIONS", styles['Heading2']))
            for a in analysis:
                for rec in a.recommendations or []:
                    elements.append(Paragraph(f"• {rec}", styles['Normal']))
            elements.append(Spacer(1, 0.2 * inch))

        # Footer
        elements.append(Spacer(1, 0.5 * inch))
        footer = Paragraph(
            f"<i>Generated by Cyber Triage Tool v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
        )
        elements.append(footer)

        # Build PDF
        doc.build(elements)

        return file_path

    async def _generate_json(
        self,
        filename: str,
        case: Case,
        evidence: List,
        artifacts: List,
        iocs: List,
        timeline: List,
        analysis: List,
    ) -> str:
        """Generate JSON report"""
        file_path = os.path.join(self.reports_dir, f"{filename}.json")

        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Cyber Triage Tool",
                "version": "1.0.0",
                "format": "JSON",
            },
            "case": {
                "case_id": case.case_id,
                "title": case.title,
                "description": case.description,
                "investigator": case.investigator,
                "status": case.status,
                "risk_score": case.risk_score,
                "risk_level": case.risk_level,
                "created_at": case.created_at.isoformat() if case.created_at else None,
            },
            "summary": {
                "total_evidence": len(evidence),
                "total_artifacts": len(artifacts),
                "total_iocs": len(iocs),
                "total_timeline_events": len(timeline),
                "total_analyses": len(analysis),
            },
            "evidence": [
                {
                    "id": e.id,
                    "name": e.name,
                    "file_type": e.file_type,
                    "file_size": e.file_size,
                    "md5_hash": e.md5_hash,
                    "sha256_hash": e.sha256_hash,
                    "processing_status": e.processing_status,
                }
                for e in evidence
            ],
            "artifacts": [
                {
                    "id": a.id,
                    "name": a.name,
                    "path": a.path,
                    "artifact_type": a.artifact_type,
                    "size": a.size,
                    "deleted": a.deleted,
                    "hidden": a.hidden,
                    "risk_score": a.risk_score,
                    "tags": a.tags,
                    "md5_hash": a.md5_hash,
                }
                for a in artifacts[:100]  # Limit
            ],
            "iocs": [
                {
                    "id": i.id,
                    "ioc_type": i.ioc_type,
                    "value": i.value,
                    "severity": i.severity,
                    "confidence": i.confidence,
                    "is_malicious": i.is_malicious,
                    "description": i.description,
                    "rule_matched": i.rule_matched,
                }
                for i in iocs
            ],
            "timeline": [
                {
                    "id": t.id,
                    "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                    "event_type": t.event_type,
                    "description": t.description,
                    "severity": t.severity,
                }
                for t in timeline[:100]  # Limit
            ],
            "analysis": [
                {
                    "id": a.id,
                    "analysis_type": a.analysis_type,
                    "model_name": a.model_name,
                    "results": a.results,
                    "confidence_score": a.confidence_score,
                    "anomalies_detected": a.anomalies_detected,
                    "recommendations": a.recommendations,
                }
                for a in analysis
            ],
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

        return file_path

    async def _generate_csv(
        self,
        filename: str,
        artifacts: List,
        iocs: List,
        timeline: List,
    ) -> str:
        """Generate CSV report (separate files for each section)"""
        file_paths = []

        # Artifacts CSV
        if artifacts:
            artifacts_path = os.path.join(self.reports_dir, f"{filename}_artifacts.csv")
            with open(artifacts_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Name", "Path", "Type", "Size", "Deleted", "Hidden", "Risk Score", "Tags", "MD5"])
                for a in artifacts:
                    writer.writerow([
                        a.id,
                        a.name,
                        a.path,
                        a.artifact_type,
                        a.size,
                        a.deleted,
                        a.hidden,
                        a.risk_score,
                        "|".join(a.tags or []),
                        a.md5_hash,
                    ])
            file_paths.append(artifacts_path)

        # IOCs CSV
        if iocs:
            iocs_path = os.path.join(self.reports_dir, f"{filename}_iocs.csv")
            with open(iocs_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Type", "Value", "Severity", "Confidence", "Malicious", "Description"])
                for i in iocs:
                    writer.writerow([
                        i.id,
                        i.ioc_type,
                        i.value,
                        i.severity,
                        i.confidence,
                        i.is_malicious,
                        i.description,
                    ])
            file_paths.append(iocs_path)

        # Timeline CSV
        if timeline:
            timeline_path = os.path.join(self.reports_dir, f"{filename}_timeline.csv")
            with open(timeline_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Timestamp", "Event Type", "Description", "Severity"])
                for t in timeline:
                    writer.writerow([
                        t.id,
                        t.timestamp.isoformat() if t.timestamp else None,
                        t.event_type,
                        t.description,
                        t.severity,
                    ])
            file_paths.append(timeline_path)

        # Return first path or create summary
        if not file_paths:
            summary_path = os.path.join(self.reports_dir, f"{filename}_summary.csv")
            with open(summary_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Section", "Count"])
                writer.writerow(["Artifacts", len(artifacts)])
                writer.writerow(["IOCs", len(iocs)])
                writer.writerow(["Timeline Events", len(timeline)])
            file_paths.append(summary_path)

        return file_paths[0]

    async def _get_case(self, case_id: str, db: AsyncSession) -> Optional[Case]:
        """Get case by ID"""
        result = await db.execute(select(Case).where(Case.case_id == case_id))
        return result.scalar_one_or_none()

    async def _get_evidence(self, case_id: str, db: AsyncSession) -> List[Evidence]:
        """Get evidence for case"""
        result = await db.execute(select(Evidence).where(Evidence.case_id == case_id))
        return result.scalars().all()

    async def _get_artifacts(self, case_id: str, db: AsyncSession) -> List[Artifact]:
        """Get artifacts for case"""
        result = await db.execute(select(Artifact).where(Artifact.case_id == case_id))
        return result.scalars().all()

    async def _get_iocs(self, case_id: str, db: AsyncSession) -> List[IOC]:
        """Get IOCs for case"""
        result = await db.execute(select(IOC).where(IOC.case_id == case_id))
        return result.scalars().all()

    async def _get_timeline(self, case_id: str, db: AsyncSession) -> List[TimelineEvent]:
        """Get timeline events for case"""
        result = await db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case_id))
        return result.scalars().all()

    async def _get_analysis(self, case_id: str, db: AsyncSession) -> List[AnalysisResult]:
        """Get analysis results for case"""
        result = await db.execute(select(AnalysisResult).where(AnalysisResult.case_id == case_id))
        return result.scalars().all()
