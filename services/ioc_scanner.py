"""
IOC Scanner Service
Scans artifacts for Indicators of Compromise
"""
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import IOC, Artifact, DetectionRule, Case


class IOCScanner:
    """Scan artifacts and data for IOCs"""

    # Built-in IOC patterns
    IOC_PATTERNS = {
        "malicious_ip": [
            r"185\.220\.101\.\d+",  # Known malicious range
            r"45\.155\.205\.\d+",
            r"192\.168\.\d+\.\d+",  # Internal (for detection)
        ],
        "suspicious_domain": [
            r"\.ru$",
            r"\.cn$",
            r"pastebin\.com",
            r"discord\.com.*api/webhooks",
        ],
        "malicious_hash_prefix": [
            r"^d41d8cd98f00b204e9800998ecf8427e",  # Empty file MD5
            r"^e99a18c428cb38d5f260853678922e03",
        ],
        "suspicious_file_path": [
            r"[/\\]Temp[/\\].*\.exe$",
            r"[/\\]AppData[/\\]Local[/\\]Temp[/\\]",
            r"[/\\]Windows[/\\]System32[/\\].*\.dll$",
            r"[/\\]Users[/\\].*[/\\]Downloads[/\\].*\.exe$",
        ],
        "registry_persistence": [
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ],
        "powershell_suspicious": [
            r"-EncodedCommand",
            r"-Enc ",
            r"Invoke-WebRequest.*-OutFile",
            r"DownloadString",
            r"Invoke-Expression",
        ],
    }

    # File extensions that are suspicious in certain contexts
    SUSPICIOUS_EXTENSIONS = [
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".msi", ".jar", ".lnk", ".pif", ".reg", ".wsf", ".hta",
    ]

    def __init__(self):
        self.compiled_patterns = {
            name: [re.compile(p, re.IGNORECASE) for p in patterns]
            for name, patterns in self.IOC_PATTERNS.items()
        }

    async def scan_case(self, case_id: str, db: AsyncSession) -> Dict[str, Any]:
        """
        Scan all artifacts in a case for IOCs

        Returns:
            Dictionary with scan results
        """
        results = {
            "iocs": [],
            "total_scanned": 0,
            "matches_found": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        # Get all artifacts for the case
        artifact_query = select(Artifact).where(Artifact.case_id == case_id)
        artifact_result = await db.execute(artifact_query)
        artifacts = artifact_result.scalars().all()

        results["total_scanned"] = len(artifacts)

        for artifact in artifacts:
            iocs = await self._scan_artifact(artifact, db)
            for ioc in iocs:
                results["iocs"].append(ioc)
                results["matches_found"] += 1
                results["by_severity"][ioc.get("severity", "low")] += 1

        return results

    async def _scan_artifact(self, artifact: Artifact, db: AsyncSession) -> List[Dict[str, Any]]:
        """Scan a single artifact for IOCs"""
        iocs_found = []

        # Check name
        name_iocs = self._check_string(artifact.name, "file_path")
        for ioc in name_iocs:
            iocs_found.append(await self._create_ioc_record(ioc, artifact, db))

        # Check path
        if artifact.path:
            path_iocs = self._check_string(artifact.path, "file_path")
            for ioc in path_iocs:
                iocs_found.append(await self._create_ioc_record(ioc, artifact, db))

        # Check tags
        if artifact.tags:
            for tag in artifact.tags:
                if tag in ["suspicious", "malware", "malicious"]:
                    iocs_found.append({
                        "ioc_type": "file_path",
                        "value": artifact.name,
                        "severity": "high",
                        "confidence": 75,
                        "description": f"Tagged as {tag}",
                        "rule_matched": f"tag_{tag}",
                        "is_malicious": True,
                    })

        # Check for suspicious extensions in temp directories
        if artifact.name:
            ext = "." + artifact.name.split(".")[-1].lower() if "." in artifact.name else ""
            if ext in self.SUSPICIOUS_EXTENSIONS:
                if artifact.path and ("temp" in artifact.path.lower() or "tmp" in artifact.path.lower()):
                    iocs_found.append({
                        "ioc_type": "file_path",
                        "value": f"{artifact.path}/{artifact.name}",
                        "severity": "medium",
                        "confidence": 60,
                        "description": f"Suspicious executable '{ext}' in temp directory",
                        "rule_matched": "suspicious_temp_executable",
                        "is_malicious": False,
                    })

        # Check hash against known bad hashes
        if artifact.md5_hash:
            hash_iocs = self._check_string(artifact.md5_hash, "malicious_hash")
            for ioc in hash_iocs:
                iocs_found.append(await self._create_ioc_record(ioc, artifact, db))

        return iocs_found

    def _check_string(self, text: str, context: str) -> List[Dict[str, Any]]:
        """Check a string against all IOC patterns"""
        matches = []

        if not text:
            return matches

        text_lower = text.lower()

        for pattern_name, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text_lower):
                    severity = self._get_severity_for_pattern(pattern_name)
                    matches.append({
                        "ioc_type": self._map_pattern_to_ioc_type(pattern_name),
                        "value": text,
                        "severity": severity,
                        "confidence": self._get_confidence_for_pattern(pattern_name),
                        "description": f"Matched {pattern_name} pattern: {text}",
                        "rule_matched": pattern_name,
                        "is_malicious": severity in ["critical", "high"],
                    })

        return matches

    def _get_severity_for_pattern(self, pattern_name: str) -> str:
        """Get severity level for a pattern type"""
        severity_map = {
            "malicious_ip": "critical",
            "suspicious_domain": "high",
            "malicious_hash_prefix": "critical",
            "suspicious_file_path": "medium",
            "registry_persistence": "high",
            "powershell_suspicious": "high",
        }
        return severity_map.get(pattern_name, "low")

    def _get_confidence_for_pattern(self, pattern_name: str) -> int:
        """Get confidence score for a pattern type"""
        confidence_map = {
            "malicious_ip": 85,
            "suspicious_domain": 60,
            "malicious_hash_prefix": 95,
            "suspicious_file_path": 70,
            "registry_persistence": 80,
            "powershell_suspicious": 75,
        }
        return confidence_map.get(pattern_name, 50)

    def _map_pattern_to_ioc_type(self, pattern_name: str) -> str:
        """Map pattern name to IOC type"""
        type_map = {
            "malicious_ip": "ip",
            "suspicious_domain": "domain",
            "malicious_hash_prefix": "hash",
            "suspicious_file_path": "file_path",
            "registry_persistence": "registry_key",
            "powershell_suspicious": "file_path",
        }
        return type_map.get(pattern_name, "unknown")

    async def _create_ioc_record(self, ioc_data: Dict[str, Any], artifact: Artifact, db: AsyncSession) -> Dict[str, Any]:
        """Create IOC database record"""
        db_ioc = IOC(
            case_id=artifact.case_id,
            ioc_type=ioc_data["ioc_type"],
            value=ioc_data["value"],
            source=f"artifact:{artifact.id}",
            confidence=ioc_data.get("confidence", 0),
            severity=ioc_data.get("severity", "medium"),
            description=ioc_data.get("description"),
            is_malicious=ioc_data.get("is_malicious", False),
            rule_matched=ioc_data.get("rule_matched"),
        )

        db.add(db_ioc)
        await db.commit()

        return ioc_data

    async def check_virustotal(self, hash_value: str, api_key: str) -> Dict[str, Any]:
        """Check hash against VirusTotal API"""
        import httpx

        if not api_key:
            return {"error": "No API key configured"}

        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": api_key}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "detected": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
                        "total": sum(data["data"]["attributes"]["last_analysis_stats"].values()),
                        "results": data["data"]["attributes"]["last_analysis_stats"],
                    }
            except Exception as e:
                return {"error": str(e)}

        return {}
