# Cyber Triage Tool - Backend

Digital Forensic Intelligence Platform - FastAPI Backend

## Features

- **Evidence Import**: Upload and process forensic disk images (RAW, E01, AFF, VMDK)
- **Artifact Extraction**: Extract files, registry entries, browser history, event logs
- **IOC Detection**: Rule-based detection of Indicators of Compromise
- **AI/ML Analysis**: Anomaly detection using Isolation Forest, risk prediction
- **Timeline Analysis**: Chronological event reconstruction
- **Report Generation**: Export findings as PDF, JSON, or CSV
- **Authentication**: JWT-based user authentication with role-based access

## Tech Stack

- **Framework**: FastAPI (Python)
- **Database**: SQLite (async) / PostgreSQL compatible
- **Forensics**: PyTSK3 (The Sleuth Kit)
- **AI/ML**: Scikit-learn (Isolation Forest, Random Forest)
- **Reports**: ReportLab (PDF), native JSON/CSV
- **Auth**: JWT (python-jose), bcrypt password hashing

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   copy .env.example .env
   # Edit .env with your settings
   ```

3. **Start the server:**
   ```bash
   # Windows
   start.bat

   # Linux/Mac
   chmod +x start.sh
   ./start.sh
   ```

4. **Access the API:**
   - API: http://localhost:8000
   - Interactive Docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

## API Endpoints

### Cases
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/cases/` | Create new case |
| GET | `/api/cases/` | List all cases |
| GET | `/api/cases/{case_id}` | Get case details |
| PUT | `/api/cases/{case_id}` | Update case |
| DELETE | `/api/cases/{case_id}` | Delete case |

### Evidence
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/evidence/upload` | Upload evidence file |
| GET | `/api/evidence/` | List evidence |
| POST | `/api/evidence/{id}/process` | Process evidence |
| DELETE | `/api/evidence/{id}` | Delete evidence |

### Artifacts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/artifacts/?case_id=xxx` | Get artifacts |
| GET | `/api/artifacts/types` | Get artifact type counts |
| GET | `/api/artifacts/stats?case_id=xxx` | Get artifact statistics |
| POST | `/api/artifacts/{id}/tag` | Add tag to artifact |

### IOCs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/iocs/?case_id=xxx` | Get IOCs |
| POST | `/api/iocs/` | Create IOC |
| POST | `/api/iocs/scan?case_id=xxx` | Scan for IOCs |
| GET | `/api/iocs/stats?case_id=xxx` | Get IOC statistics |

### Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analysis/anomaly-detection` | Run anomaly detection |
| POST | `/api/analysis/risk-prediction` | Predict risk score |
| POST | `/api/analysis/behavioral-analysis` | Analyze behavior patterns |
| GET | `/api/analysis/results?case_id=xxx` | Get analysis results |

### Timeline
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/timeline/?case_id=xxx` | Get timeline events |
| POST | `/api/timeline/generate` | Generate timeline |
| POST | `/api/timeline/` | Create timeline event |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/reports/generate` | Generate report |
| GET | `/api/reports/` | List reports |
| GET | `/api/reports/{id}/download` | Download report |

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register user |
| POST | `/api/auth/login` | Login |
| GET | `/api/auth/me` | Get current user |

## Example Usage

### Create a Case
```bash
curl -X POST http://localhost:8000/api/cases/ \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Malware Investigation",
    "description": "Suspected malware infection on workstation",
    "investigator": "John Doe"
  }'
```

### Upload Evidence
```bash
curl -X POST http://localhost:8000/api/evidence/upload \
  -F "file=@disk_image.raw" \
  -F "case_id=CTF-2025-001"
```

### Process Evidence
```bash
curl -X POST http://localhost:8000/api/evidence/1/process
```

### Run IOC Scan
```bash
curl -X POST http://localhost:8000/api/iocs/scan?case_id=CTF-2025-001
```

### Run Risk Analysis
```bash
curl -X POST http://localhost:8000/api/analysis/risk-prediction \
  -H "Content-Type: application/json" \
  -d '{"case_id": "CTF-2025-001"}'
```

### Generate Report
```bash
curl -X POST http://localhost:8000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "CTF-2025-001",
    "report_type": "pdf",
    "include_artifacts": true,
    "include_iocs": true,
    "include_timeline": true,
    "include_analysis": true
  }'
```

## Project Structure

```
backend/
├── api/
│   └── routes/
│       ├── cases.py        # Case management
│       ├── evidence.py     # Evidence upload/processing
│       ├── artifacts.py    # Artifact queries
│       ├── iocs.py         # IOC detection
│       ├── analysis.py     # AI/ML analysis
│       ├── timeline.py     # Timeline events
│       ├── reports.py      # Report generation
│       └── auth.py         # Authentication
├── services/
│   ├── evidence_processor.py   # Disk image processing
│   ├── ioc_scanner.py          # IOC detection logic
│   ├── ai_engine.py            # ML analysis
│   ├── timeline_generator.py   # Timeline creation
│   └── report_generator.py     # Report export
├── database/
│   ├── models.py           # SQLAlchemy models
│   └── database.py         # DB connection
├── main.py                 # FastAPI application
├── requirements.txt        # Python dependencies
└── .env.example            # Environment template
```

## Database Models

- **Case**: Investigation case management
- **Evidence**: Forensic evidence files
- **Artifact**: Extracted artifacts (files, registry, network)
- **IOC**: Indicators of Compromise
- **TimelineEvent**: Chronological events
- **AnalysisResult**: AI/ML analysis output
- **DetectionRule**: Detection patterns
- **Report**: Generated reports
- **User**: User accounts

## Risk Scoring

The system calculates risk scores based on:

1. **Artifact Risk (30%)**: Suspicious files, deleted items, hidden files
2. **IOC Risk (50%)**: Malicious indicators, severity levels
3. **Behavioral Risk (20%)**: Unusual patterns, critical events

Risk Levels:
- **0-25**: Low Risk
- **25-50**: Medium Risk
- **50-75**: High Risk
- **75-100**: Critical Risk

## Detection Rules

Built-in detection patterns:
- Malicious IP addresses
- Suspicious domains
- Known malware hash prefixes
- Suspicious file paths (temp directories)
- Registry persistence mechanisms
- PowerShell attack patterns

## License

MIT License - Academic/Research Use
