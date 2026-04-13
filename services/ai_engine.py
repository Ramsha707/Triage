"""
AI/ML Engine Service
Anomaly detection, risk prediction, and behavioral analysis
"""
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AnalysisResult, Artifact, IOC, TimelineEvent, Case

# Try to import sklearn
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. Using rule-based analysis.")


class AIEngine:
    """AI/ML analysis engine for forensic data"""

    def __init__(self):
        self.model_version = "1.0.0"
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None

    async def detect_anomalies(self, request, db: AsyncSession) -> AnalysisResult:
        """
        Detect anomalies using Isolation Forest algorithm

        Analyzes:
        - File sizes and types
        - Timestamps patterns
        - File locations
        """
        if not SKLEARN_AVAILABLE:
            return await self._rule_based_anomaly_detection(request, db)

        # Get artifacts for analysis
        artifacts = await self._get_case_artifacts(request.case_id, db)

        if len(artifacts) < 3:
            return await self._create_analysis_result(
                request.case_id,
                "anomaly_detection",
                {"error": "Insufficient data for anomaly detection", "min_required": 3},
                0,
                [],
                db,
            )

        # Feature extraction
        features = self._extract_features(artifacts)

        if features is None or len(features) < 3:
            return await self._create_analysis_result(
                request.case_id,
                "anomaly_detection",
                {"error": "Feature extraction failed"},
                0,
                [],
                db,
            )

        # Run Isolation Forest
        contamination = {"low": 0.1, "medium": 0.05, "high": 0.02}.get(request.sensitivity, 0.05)
        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )

        predictions = iso_forest.fit_predict(features)
        scores = iso_forest.decision_function(features)

        # Process results
        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly
                anomalies.append({
                    "artifact_id": artifacts[i].id,
                    "artifact_name": artifacts[i].name,
                    "anomaly_score": float(score),
                    "reason": self._explain_anomaly(artifacts[i], features[i]),
                })

        recommendations = self._generate_anomaly_recommendations(anomalies)

        return await self._create_analysis_result(
            request.case_id,
            "anomaly_detection",
            {
                "total_analyzed": len(artifacts),
                "anomalies_detected": len(anomalies),
                "anomaly_details": anomalies,
                "contamination_level": contamination,
            },
            len(anomalies),
            recommendations,
            db,
            confidence=min(95, 50 + len(anomalies) * 5),
        )

    async def predict_risk(self, request, db: AsyncSession) -> AnalysisResult:
        """
        Predict overall risk score for a case

        Uses multiple factors:
        - Artifact characteristics
        - IOC presence
        - Behavioral patterns
        """
        # Gather data
        artifacts = await self._get_case_artifacts(request.case_id, db)
        iocs = await self._get_case_iocs(request.case_id, db)
        timeline = await self._get_case_timeline(request.case_id, db)

        # Calculate risk components
        artifact_risk = self._calculate_artifact_risk(artifacts)
        ioc_risk = self._calculate_ioc_risk(iocs)
        behavioral_risk = self._calculate_behavioral_risk(timeline)

        # Weighted combination
        overall_score = (
            artifact_risk["score"] * 0.3 +
            ioc_risk["score"] * 0.5 +
            behavioral_risk["score"] * 0.2
        )

        # Normalize to 0-100
        overall_score = min(100, max(0, overall_score))

        recommendations = self._generate_risk_recommendations({
            "artifact_risk": artifact_risk,
            "ioc_risk": ioc_risk,
            "behavioral_risk": behavioral_risk,
        })

        return await self._create_analysis_result(
            request.case_id,
            "risk_prediction",
            {
                "overall_risk_score": round(overall_score, 2),
                "risk_level": self._score_to_level(overall_score),
                "artifact_risk": artifact_risk,
                "ioc_risk": ioc_risk,
                "behavioral_risk": behavioral_risk,
                "factors": {
                    "suspicious_files": artifact_risk.get("suspicious_count", 0),
                    "deleted_files": artifact_risk.get("deleted_count", 0),
                    "malicious_iocs": ioc_risk.get("malicious_count", 0),
                    "critical_events": behavioral_risk.get("critical_events", 0),
                },
            },
            0,
            recommendations,
            db,
            confidence=min(95, 40 + len(artifacts) + len(iocs) * 2),
        )

    async def analyze_behavior(self, request, db: AsyncSession) -> AnalysisResult:
        """
        Analyze behavioral patterns

        Looks for:
        - Unusual access times
        - Abnormal sequences
        - Suspicious patterns
        """
        timeline = await self._get_case_timeline(request.case_id, db)
        artifacts = await self._get_case_artifacts(request.case_id, db)

        patterns_found = []

        # Analyze file access patterns
        if "file_access" in request.analyze_patterns:
            file_patterns = self._analyze_file_access_patterns(artifacts)
            patterns_found.extend(file_patterns)

        # Analyze login times
        if "login_times" in request.analyze_patterns:
            login_patterns = self._analyze_login_patterns(timeline)
            patterns_found.extend(login_patterns)

        # Analyze network connections
        if "network_connections" in request.analyze_patterns:
            network_patterns = self._analyze_network_patterns(timeline)
            patterns_found.extend(network_patterns)

        recommendations = self._generate_behavior_recommendations(patterns_found)

        return await self._create_analysis_result(
            request.case_id,
            "behavioral_analysis",
            {
                "patterns_analyzed": len(request.analyze_patterns),
                "patterns_found": len(patterns_found),
                "pattern_details": patterns_found,
            },
            len([p for p in patterns_found if p.get("severity") in ["high", "critical"]]),
            recommendations,
            db,
            confidence=min(90, 30 + len(timeline) * 2),
        )

    def _extract_features(self, artifacts: List[Artifact]) -> Optional[np.ndarray]:
        """Extract numerical features from artifacts for ML"""
        if not SKLEARN_AVAILABLE or len(artifacts) < 3:
            return None

        features = []
        for artifact in artifacts:
            feature_vector = [
                artifact.size or 0,
                1 if artifact.deleted else 0,
                1 if artifact.hidden else 0,
                artifact.risk_score or 0,
                len(artifact.tags or []),
                # Time-based features
                (artifact.modified_time - artifact.created_time).total_seconds() if artifact.created_time and artifact.modified_time else 0,
            ]
            features.append(feature_vector)

        return np.array(features)

    def _explain_anomaly(self, artifact: Artifact, features: np.ndarray) -> str:
        """Explain why an artifact was flagged as anomalous"""
        reasons = []

        if features[0] > 10000000:  # Large file
            reasons.append("unusually large file")
        if features[1] == 1:  # Deleted
            reasons.append("deleted file")
        if features[2] == 1:  # Hidden
            reasons.append("hidden file")
        if features[3] > 50:  # High risk score
            reasons.append("high risk score")
        if features[4] > 2:  # Multiple tags
            reasons.append("multiple suspicious tags")

        return ", ".join(reasons) if reasons else "statistical outlier"

    def _calculate_artifact_risk(self, artifacts: List[Artifact]) -> Dict[str, Any]:
        """Calculate risk score from artifacts"""
        if not artifacts:
            return {"score": 0, "suspicious_count": 0, "deleted_count": 0}

        suspicious_count = sum(1 for a in artifacts if a.risk_score and a.risk_score > 50)
        deleted_count = sum(1 for a in artifacts if a.deleted)
        hidden_count = sum(1 for a in artifacts if a.hidden)

        score = (
            (suspicious_count / len(artifacts)) * 100 +
            (deleted_count / len(artifacts)) * 30 +
            (hidden_count / len(artifacts)) * 20
        )

        return {
            "score": min(100, score),
            "suspicious_count": suspicious_count,
            "deleted_count": deleted_count,
            "hidden_count": hidden_count,
            "total_artifacts": len(artifacts),
        }

    def _calculate_ioc_risk(self, iocs: List[IOC]) -> Dict[str, Any]:
        """Calculate risk score from IOCs"""
        if not iocs:
            return {"score": 0, "malicious_count": 0}

        malicious_count = sum(1 for i in iocs if i.is_malicious)
        critical_count = sum(1 for i in iocs if i.severity == "critical")
        high_count = sum(1 for i in iocs if i.severity == "high")

        score = (
            (malicious_count / len(iocs)) * 100 +
            critical_count * 20 +
            high_count * 10
        )

        return {
            "score": min(100, score),
            "malicious_count": malicious_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "total_iocs": len(iocs),
        }

    def _calculate_behavioral_risk(self, events: List[TimelineEvent]) -> Dict[str, Any]:
        """Calculate risk score from timeline events"""
        if not events:
            return {"score": 0, "critical_events": 0}

        critical_events = sum(1 for e in events if e.severity == "critical")
        high_events = sum(1 for e in events if e.severity == "high")
        warning_events = sum(1 for e in events if e.severity == "warning")

        score = critical_events * 30 + high_events * 15 + warning_events * 5

        return {
            "score": min(100, score),
            "critical_events": critical_events,
            "high_events": high_events,
            "warning_events": warning_events,
            "total_events": len(events),
        }

    def _score_to_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"

    def _generate_anomaly_recommendations(self, anomalies: List[Dict]) -> List[str]:
        """Generate recommendations based on anomalies"""
        recommendations = []

        if len(anomalies) > 10:
            recommendations.append("High number of anomalies detected - prioritize investigation")
        if any(a.get("reason", "").find("hidden") >= 0 for a in anomalies):
            recommendations.append("Investigate hidden files for potential malware or data exfiltration")
        if any(a.get("reason", "").find("deleted") >= 0 for a in anomalies):
            recommendations.append("Recover and analyze deleted files - may contain evidence of malicious activity")

        if not recommendations:
            recommendations.append("Continue monitoring - no immediate action required")

        return recommendations

    def _generate_risk_recommendations(self, risks: Dict) -> List[str]:
        """Generate recommendations based on risk analysis"""
        recommendations = []

        if risks["ioc_risk"]["malicious_count"] > 0:
            recommendations.append(f"Isolate affected system - {risks['ioc_risk']['malicious_count']} malicious IOCs detected")
        if risks["artifact_risk"]["suspicious_count"] > 0:
            recommendations.append(f"Analyze {risks['artifact_risk']['suspicious_count']} suspicious files in sandbox environment")
        if risks["behavioral_risk"]["critical_events"] > 0:
            recommendations.append(f"Investigate {risks['behavioral_risk']['critical_events']} critical events immediately")

        return recommendations

    def _generate_behavior_recommendations(self, patterns: List[Dict]) -> List[str]:
        """Generate recommendations based on behavioral analysis"""
        recommendations = []

        high_severity = [p for p in patterns if p.get("severity") in ["high", "critical"]]
        if high_severity:
            recommendations.append(f"Investigate {len(high_severity)} high-severity behavioral patterns")

        return recommendations

    async def _create_analysis_result(
        self,
        case_id: str,
        analysis_type: str,
        results: Dict,
        anomalies_count: int,
        recommendations: List[str],
        db: AsyncSession,
        confidence: float = 0.0,
    ) -> AnalysisResult:
        """Create and save analysis result"""
        analysis = AnalysisResult(
            case_id=case_id,
            analysis_type=analysis_type,
            model_name="IsolationForest" if analysis_type == "anomaly_detection" else "RiskModel",
            model_version=self.model_version,
            results=results,
            confidence_score=confidence,
            anomalies_detected=anomalies_count,
            recommendations=recommendations,
        )

        db.add(analysis)
        await db.commit()

        return analysis

    async def _get_case_artifacts(self, case_id: str, db: AsyncSession) -> List[Artifact]:
        """Get all artifacts for a case"""
        result = await db.execute(select(Artifact).where(Artifact.case_id == case_id))
        return result.scalars().all()

    async def _get_case_iocs(self, case_id: str, db: AsyncSession) -> List[IOC]:
        """Get all IOCs for a case"""
        result = await db.execute(select(IOC).where(IOC.case_id == case_id))
        return result.scalars().all()

    async def _get_case_timeline(self, case_id: str, db: AsyncSession) -> List[TimelineEvent]:
        """Get all timeline events for a case"""
        result = await db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case_id))
        return result.scalars().all()

    async def _rule_based_anomaly_detection(self, request, db: AsyncSession) -> AnalysisResult:
        """Fallback rule-based anomaly detection when sklearn is not available"""
        artifacts = await self._get_case_artifacts(request.case_id, db)

        anomalies = []
        for artifact in artifacts:
            reasons = []

            if artifact.deleted:
                reasons.append("deleted file")
            if artifact.hidden:
                reasons.append("hidden file")
            if artifact.risk_score and artifact.risk_score > 50:
                reasons.append("high risk score")
            if artifact.tags and len(artifact.tags) > 0:
                reasons.append(f"tagged: {', '.join(artifact.tags)}")

            if reasons:
                anomalies.append({
                    "artifact_id": artifact.id,
                    "artifact_name": artifact.name,
                    "anomaly_score": artifact.risk_score or 50,
                    "reason": ", ".join(reasons),
                })

        recommendations = self._generate_anomaly_recommendations(anomalies)

        return await self._create_analysis_result(
            request.case_id,
            "anomaly_detection",
            {
                "total_analyzed": len(artifacts),
                "anomalies_detected": len(anomalies),
                "anomaly_details": anomalies,
                "method": "rule_based",
            },
            len(anomalies),
            recommendations,
            db,
            confidence=min(80, 40 + len(anomalies) * 5),
        )

    # Additional behavioral analysis methods
    def _analyze_file_access_patterns(self, artifacts: List[Artifact]) -> List[Dict]:
        """Analyze file access patterns for anomalies"""
        patterns = []

        # Check for bulk file access
        if len(artifacts) > 100:
            patterns.append({
                "pattern": "bulk_file_access",
                "severity": "medium",
                "description": f"Large number of files accessed: {len(artifacts)}",
            })

        # Check for temp directory activity
        temp_files = [a for a in artifacts if a.path and ("temp" in a.path.lower() or "tmp" in a.path.lower())]
        if len(temp_files) > 5:
            patterns.append({
                "pattern": "suspicious_temp_activity",
                "severity": "high",
                "description": f"High activity in temp directories: {len(temp_files)} files",
            })

        return patterns

    def _analyze_login_patterns(self, timeline: List[TimelineEvent]) -> List[Dict]:
        """Analyze login patterns for anomalies"""
        patterns = []

        login_events = [e for e in timeline if e.event_type == "user_login"]

        # Check for off-hours logins
        for event in login_events:
            hour = event.timestamp.hour if event.timestamp else 12
            if hour < 6 or hour > 22:
                patterns.append({
                    "pattern": "off_hours_login",
                    "severity": "medium",
                    "description": f"Login detected at unusual hour: {hour}:00",
                })

        return patterns

    def _analyze_network_patterns(self, timeline: List[TimelineEvent]) -> List[Dict]:
        """Analyze network patterns for anomalies"""
        patterns = []

        network_events = [e for e in timeline if e.event_type == "network_connection"]

        if len(network_events) > 50:
            patterns.append({
                "pattern": "excessive_network_activity",
                "severity": "medium",
                "description": f"High network activity: {len(network_events)} connections",
            })

        return patterns
