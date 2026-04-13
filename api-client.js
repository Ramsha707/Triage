/* =========================================
   CYBER TRIAGE - API CLIENT
   Connects frontend with backend API
   ========================================= */

const API_BASE_URL = 'http://localhost:8000/api';

// API Client class
class CyberTriageAPI {
  constructor(baseUrl = API_BASE_URL) {
    this.baseUrl = baseUrl;
    this.token = localStorage.getItem('access_token');
  }

  // Set authentication token
  setToken(token) {
    this.token = token;
    localStorage.setItem('access_token', token);
  }

  // Clear authentication
  logout() {
    this.token = null;
    localStorage.removeItem('access_token');
  }

  // Generic request method
  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const config = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(this.token && { 'Authorization': `Bearer ${this.token}` }),
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, config);

      if (response.status === 401) {
        this.logout();
        window.location.href = '/login.html';
        throw new Error('Unauthorized');
      }

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Request failed');
      }

      return await response.json();
    } catch (error) {
      console.error(`API Error (${endpoint}):`, error);
      throw error;
    }
  }

  // =====================
  // CASES API
  // =====================

  async getCases(statusFilter = null) {
    const endpoint = statusFilter
      ? `/cases/?status_filter=${statusFilter}`
      : '/cases/';
    return await this.request(endpoint);
  }

  async getCase(caseId) {
    return await this.request(`/cases/${caseId}`);
  }

  async createCase(caseData) {
    return await this.request('/cases/', {
      method: 'POST',
      body: JSON.stringify(caseData),
    });
  }

  async updateCase(caseId, caseData) {
    return await this.request(`/cases/${caseId}`, {
      method: 'PUT',
      body: JSON.stringify(caseData),
    });
  }

  async deleteCase(caseId) {
    return await this.request(`/cases/${caseId}`, {
      method: 'DELETE',
    });
  }

  // =====================
  // DASHBOARD API
  // =====================

  async getDashboardStats() {
    return await this.request('/dashboard/stats');
  }

  // =====================
  // EVIDENCE API
  // =====================

  async getEvidence(caseId = null) {
    const endpoint = caseId
      ? `/evidence/?case_id=${caseId}`
      : '/evidence/';
    return await this.request(endpoint);
  }

  async uploadEvidence(file, caseId, description = null) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('case_id', caseId);
    if (description) formData.append('description', description);

    const response = await fetch(`${this.baseUrl}/evidence/upload`, {
      method: 'POST',
      headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Upload failed');
    }

    return await response.json();
  }

  async processEvidence(evidenceId) {
    return await this.request(`/evidence/${evidenceId}/process`, {
      method: 'POST',
    });
  }

  // =====================
  // ARTIFACTS API
  // =====================

  async getArtifacts(caseId, filters = {}) {
    const params = new URLSearchParams({ case_id: caseId });
    if (filters.artifact_type) params.append('artifact_type', filters.artifact_type);
    if (filters.deleted !== undefined) params.append('deleted', filters.deleted);
    if (filters.search) params.append('search', filters.search);
    if (filters.limit) params.append('limit', filters.limit);

    return await this.request(`/artifacts/?${params}`);
  }

  async getArtifactStats(caseId) {
    return await this.request(`/artifacts/stats?case_id=${caseId}`);
  }

  async addArtifactTag(artifactId, tag) {
    return await this.request(`/artifacts/${artifactId}/tag?tag=${tag}`, {
      method: 'POST',
    });
  }

  // =====================
  // IOCs API
  // =====================

  async getIOCs(caseId, filters = {}) {
    const params = new URLSearchParams({ case_id: caseId });
    if (filters.ioc_type) params.append('ioc_type', filters.ioc_type);
    if (filters.severity) params.append('severity', filters.severity);

    return await this.request(`/iocs/?${params}`);
  }

  async getIOCStats(caseId) {
    return await this.request(`/iocs/stats?case_id=${caseId}`);
  }

  async scanForIOCs(caseId) {
    return await this.request(`/iocs/scan?case_id=${caseId}`, {
      method: 'POST',
    });
  }

  // =====================
  // ANALYSIS API
  // =====================

  async runAnomalyDetection(caseId, sensitivity = 'medium') {
    return await this.request('/analysis/anomaly-detection', {
      method: 'POST',
      body: JSON.stringify({ case_id: caseId, sensitivity }),
    });
  }

  async runRiskPrediction(caseId) {
    return await this.request('/analysis/risk-prediction', {
      method: 'POST',
      body: JSON.stringify({ case_id: caseId }),
    });
  }

  async getAnalysisResults(caseId) {
    return await this.request(`/analysis/results?case_id=${caseId}`);
  }

  // =====================
  // TIMELINE API
  // =====================

  async getTimeline(caseId, filters = {}) {
    const params = new URLSearchParams({ case_id: caseId });
    if (filters.start_time) params.append('start_time', filters.start_time);
    if (filters.end_time) params.append('end_time', filters.end_time);
    if (filters.event_type) params.append('event_type', filters.event_type);

    return await this.request(`/timeline/?${params}`);
  }

  async generateTimeline(caseId) {
    return await this.request('/timeline/generate', {
      method: 'POST',
      body: JSON.stringify({ case_id: caseId }),
    });
  }

  // =====================
  // REPORTS API
  // =====================

  async generateReport(caseId, reportType = 'json', options = {}) {
    return await this.request('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({
        case_id: caseId,
        report_type: reportType,
        include_artifacts: options.includeArtifacts !== false,
        include_iocs: options.includeIOCs !== false,
        include_timeline: options.includeTimeline !== false,
        include_analysis: options.includeAnalysis !== false,
      }),
    });
  }

  async getReports(caseId = null) {
    const endpoint = caseId
      ? `/reports/?case_id=${caseId}`
      : '/reports/';
    return await this.request(endpoint);
  }

  async downloadReport(reportId) {
    const response = await fetch(`${this.baseUrl}/reports/${reportId}/download`, {
      headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
    });

    if (!response.ok) {
      throw new Error('Download failed');
    }

    return await response.blob();
  }

  // =====================
  // AUTH API
  // =====================

  async login(username, password) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });

    this.setToken(response.access_token);
    return response;
  }

  async register(username, email, password, fullName = null) {
    return await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password, full_name: fullName }),
    });
  }

  async getCurrentUser() {
    return await this.request('/auth/me');
  }
}

// Create global API instance
const api = new CyberTriageAPI();

// =====================
// UI UPDATE FUNCTIONS
// =====================

// Update dashboard with real data
async function updateDashboard() {
  try {
    const stats = await api.getDashboardStats();

    // Update counters
    if (document.getElementById('case-counter')) {
      document.getElementById('case-counter').textContent = stats.total_cases || 0;
    }
    if (document.getElementById('evidence-counter')) {
      document.getElementById('evidence-counter').textContent = stats.total_evidence || 0;
    }
    if (document.getElementById('artifact-counter')) {
      document.getElementById('artifact-counter').textContent = stats.total_artifacts || 0;
    }
    if (document.getElementById('ioc-counter')) {
      document.getElementById('ioc-counter').textContent = stats.total_iocs || 0;
    }

    // Update risk display
    if (stats.high_risk_cases > 0) {
      document.getElementById('risk-counter').textContent = stats.high_risk_cases;
    }
  } catch (error) {
    console.error('Failed to update dashboard:', error);
  }
}

// Load cases into table
async function loadCasesTable() {
  try {
    const cases = await api.getCases();
    const tbody = document.querySelector('#casesTable tbody');

    if (!tbody) return;

    tbody.innerHTML = cases.map(caseItem => `
      <tr data-case-id="${caseItem.case_id}">
        <td class="mono">${caseItem.case_id}</td>
        <td>${caseItem.title}</td>
        <td>${caseItem.investigator}</td>
        <td>
          <span class="tag tag-${caseItem.risk_level === 'critical' ? 'red' : caseItem.risk_level === 'high' ? 'amber' : 'green'}">
            ${caseItem.risk_level.toUpperCase()}
          </span>
        </td>
        <td class="mono">${caseItem.risk_score?.toFixed(1) || 0}</td>
        <td>${caseItem.status}</td>
        <td>
          <button class="btn-ghost" onclick="viewCase('${caseItem.case_id}')">View</button>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Failed to load cases:', error);
  }
}

// Load artifacts into table
async function loadArtifactsTable(caseId, filters = {}) {
  try {
    const artifacts = await api.getArtifacts(caseId, filters);
    const tbody = document.querySelector('#artifactsTable tbody');

    if (!tbody) return;

    tbody.innerHTML = artifacts.map(artifact => `
      <tr data-artifact-id="${artifact.id}" data-type="${artifact.artifact_type}">
        <td>
          <span class="file-type ${getFileTypeClass(artifact.file_type)}">
            ${artifact.file_type || 'FILE'}
          </span>
        </td>
        <td class="mono">${artifact.name}</td>
        <td class="path-cell mono">${artifact.path || 'N/A'}</td>
        <td class="mono">${formatFileSize(artifact.size)}</td>
        <td class="hash-cell mono">${artifact.md5_hash ? artifact.md5_hash.substring(0, 16) + '...' : 'N/A'}</td>
        <td>
          ${artifact.deleted ? '<span class="tag tag-red">DELETED</span>' : '<span class="tag-active">ACTIVE</span>'}
        </td>
        <td>
          ${artifact.tags?.map(tag => `<span class="tag tag-blue">${tag}</span>`).join('') || ''}
        </td>
        <td>
          <span class="risk-${artifact.risk_score >= 50 ? 'high' : artifact.risk_score >= 25 ? 'med' : 'low'}">
            ${artifact.risk_score?.toFixed(0) || 0}
          </span>
        </td>
      </tr>
    `).join('');
  } catch (error) {
    console.error('Failed to load artifacts:', error);
  }
}

// Load IOCs
async function loadIOCs(caseId) {
  try {
    const iocs = await api.getIOCs(caseId);
    const container = document.getElementById('iocList');

    if (!container) return;

    container.innerHTML = iocs.map(ioc => `
      <div class="ioc-row">
        <div class="ioc-label">${ioc.ioc_type.toUpperCase()}</div>
        <div class="ioc-bar-wrap">
          <div class="ioc-bar ${ioc.severity === 'critical' ? '' : 'warning-bar'}" style="width: ${ioc.confidence}%"></div>
        </div>
        <div class="ioc-score">${ioc.confidence}%</div>
      </div>
    `).join('');
  } catch (error) {
    console.error('Failed to load IOCs:', error);
  }
}

// Load timeline
async function loadTimeline(caseId) {
  try {
    const events = await api.getTimeline(caseId);
    const container = document.getElementById('timelineEvents');

    if (!container) return;

    events.forEach((event, index) => {
      const el = document.createElement('div');
      el.className = 'timeline-event';
      el.style.top = `${index * 80}px`;
      el.innerHTML = `
        <div class="event-time mono">${formatTimestamp(event.timestamp)}</div>
        <div class="event-dot ${event.severity === 'critical' ? 'critical-dot' : event.severity === 'warning' ? 'warning-dot' : 'info-dot'}"></div>
        <div class="event-card">
          <div class="event-title">${event.event_type.replace(/_/g, ' ').toUpperCase()}</div>
          <div class="event-detail mono">${event.description}</div>
        </div>
      `;
      container.appendChild(el);
    });
  } catch (error) {
    console.error('Failed to load timeline:', error);
  }
}

// Handle file upload
async function handleFileUpload(file, caseId) {
  try {
    const evidence = await api.uploadEvidence(file, caseId);
    showToast(`✓ Evidence uploaded: ${file.name}`);

    // Start processing
    await api.processEvidence(evidence.id);
    showToast('✓ Processing started...');

    return evidence;
  } catch (error) {
    console.error('Upload failed:', error);
    showToast(`✗ Upload failed: ${error.message}`);
    throw error;
  }
}

// Run analysis
async function runFullAnalysis(caseId) {
  try {
    showToast('Running IOC scan...');
    await api.scanForIOCs(caseId);

    showToast('Running anomaly detection...');
    await api.runAnomalyDetection(caseId);

    showToast('Calculating risk score...');
    await api.runRiskPrediction(caseId);

    showToast('✓ Analysis complete!');

    // Refresh data
    await updateDashboard();
    await loadIOCs(caseId);

  } catch (error) {
    console.error('Analysis failed:', error);
    showToast(`✗ Analysis error: ${error.message}`);
  }
}

// Generate report
async function generateReport(caseId, format = 'pdf') {
  try {
    showToast(`Generating ${format.toUpperCase()} report...`);
    const result = await api.generateReport(caseId, format);
    showToast(`✓ Report generated: ${result.file_name}`);
    return result;
  } catch (error) {
    console.error('Report generation failed:', error);
    showToast(`✗ Report error: ${error.message}`);
    throw error;
  }
}

// Helper functions
function getFileTypeClass(type) {
  if (!type) return '';
  const t = type.toLowerCase();
  if (t.includes('exe') || t.includes('dll')) return 'exe-type';
  if (t.includes('reg')) return 'reg-type';
  if (t.includes('deleted')) return 'del-type';
  if (t.includes('hidden')) return 'hid-type';
  return '';
}

function formatFileSize(bytes) {
  if (!bytes) return 'N/A';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(1) + ' GB';
}

function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A';
  return new Date(timestamp).toLocaleString();
}

function showToast(message) {
  const toast = document.getElementById('exportToast');
  if (toast) {
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 4000);
  } else {
    console.log('Toast:', message);
  }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
  updateDashboard();
  loadCasesTable();
});
