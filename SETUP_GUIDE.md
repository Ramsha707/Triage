# Cyber Triage Tool - Complete Setup Guide

## Project Structure

```
Cyber_triage/
├── backend/                    # FastAPI Backend
│   ├── api/routes/            # API endpoints
│   ├── services/              # Business logic
│   ├── database/              # Models & DB config
│   ├── main.py                # FastAPI app
│   ├── requirements.txt       # Python dependencies
│   ├── seed_mock_data.py      # Test data seeder
│   └── start.bat              # Windows startup script
│
├── index.html                 # Frontend UI
├── styles.css                 # Frontend styles
├── app.js                     # Frontend logic
└── api-client.js              # API integration layer
```

## Quick Start (Windows)

### Step 1: Install Python Dependencies

```bash
cd Cyber_triage\backend
pip install -r requirements.txt
```

### Step 2: Seed Mock Data (for testing)

```bash
python seed_mock_data.py
```

This creates:
- 2 sample cases (Malware Investigation, Insider Threat)
- Sample evidence, artifacts, IOCs
- Timeline events
- Detection rules

### Step 3: Start Backend Server

```bash
# Option 1: Using startup script
start.bat

# Option 2: Manual
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 4: Open Frontend

Open `Cyber_triage\index.html` in your browser.

The dashboard will automatically connect to the backend and load real data.

## API Documentation

Once the server is running, access:
- **Interactive API docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health check**: http://localhost:8000/api/health

## Testing the API

### Create a Case
```bash
curl -X POST http://localhost:8000/api/cases/ ^
  -H "Content-Type: application/json" ^
  -d "{\"title\":\"Test Case\",\"investigator\":\"John Doe\"}"
```

### Get Dashboard Stats
```bash
curl http://localhost:8000/api/dashboard/stats
```

### Upload Evidence
```bash
curl -X POST http://localhost:8000/api/evidence/upload ^
  -F "file=@disk_image.raw" ^
  -F "case_id=CTF-2025-001"
```

### Run Analysis
```bash
curl -X POST http://localhost:8000/api/analysis/risk-prediction ^
  -H "Content-Type: application/json" ^
  -d "{\"case_id\":\"CTF-2025-001\"}"
```

## Frontend Integration

The frontend automatically connects to the backend via `api-client.js`.

### Features Connected to Backend:

1. **Dashboard Stats** - Real case/artifact/IOC counts
2. **Evidence Import** - Upload and process forensic images
3. **Artifact Explorer** - Filter and search artifacts
4. **IOC Analysis** - Scan for indicators of compromise
5. **Timeline** - View chronological events
6. **Reports** - Generate PDF/JSON/CSV reports

## Troubleshooting

### Backend won't start
```bash
# Check Python version (need 3.10+)
python --version

# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

### Database errors
```bash
# Delete existing database and reseed
del cyber_triage.db
python seed_mock_data.py
```

### Frontend can't connect to backend
- Ensure backend is running on port 8000
- Check browser console for CORS errors
- Verify `api-client.js` has correct API URL

### pytsk3 installation fails
pytsk3 is optional. The system will use mock processing if not available.

For Windows, you may need pre-compiled wheels:
```bash
pip install pytsk3==20220812 --only-binary :all:
```

## Production Deployment

### Environment Variables

Create `.env` file in `backend/`:

```env
DATABASE_URL=sqlite+aiosqlite:///./cyber_triage.db
SECRET_KEY=your-production-secret-key
EVIDENCE_DIR=./evidence
REPORTS_DIR=./reports
```

### Run with Production Settings

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

## Sample Workflow

1. **Create Case**
   - Navigate to Dashboard
   - Click "New Case"
   - Enter case details

2. **Upload Evidence**
   - Go to Evidence Import
   - Drag & drop disk image
   - Wait for processing

3. **View Artifacts**
   - Navigate to Artifact Explorer
   - Filter by type (files, registry, network)
   - Search for specific items

4. **Run Analysis**
   - Click "Scan for IOCs"
   - Run AI/ML anomaly detection
   - View risk score

5. **Generate Report**
   - Go to Reports section
   - Select format (PDF/JSON/CSV)
   - Download report

## Features Checklist

- [x] Case Management
- [x] Evidence Upload (RAW, E01, AFF, VMDK)
- [x] Artifact Extraction (mock/real)
- [x] IOC Detection (rule-based)
- [x] AI/ML Analysis (Isolation Forest)
- [x] Timeline Generation
- [x] Report Export (PDF, JSON, CSV)
- [x] User Authentication (JWT)
- [x] Dashboard with Real-time Stats
- [x] Dark Theme Cyber UI

## Next Steps

1. Install real forensic tools (pytsk3, libewf)
2. Connect VirusTotal API for hash lookups
3. Add more detection rules
4. Train custom ML models on attack data
5. Implement chain of custody logging

## Support

For issues or questions:
1. Check API docs at http://localhost:8000/docs
2. Review backend logs for errors
3. Check browser console for frontend issues
