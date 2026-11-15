/**
 * API service for communicating with FastAPI backend endpoints.
 */

const API_BASE = '/api';

export async function analyzeUrl(url, customWeights = null) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      url,
      custom_weights: customWeights,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Analysis failed with status ${response.status}`);
  }

  return response.json();
}

export async function fetchScans(limit = 50, offset = 0) {
  const response = await fetch(`${API_BASE}/scans?limit=${limit}&offset=${offset}`);
  if (!response.ok) {
    throw new Error('Failed to fetch scan history');
  }
  return response.json();
}

export async function fetchScanDetails(scanId) {
  const response = await fetch(`${API_BASE}/scans/${scanId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch scan #${scanId}`);
  }
  return response.json();
}

export async function deleteScan(scanId) {
  const response = await fetch(`${API_BASE}/scans/${scanId}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    throw new Error(`Failed to delete scan #${scanId}`);
  }
  return response.json();
}

export async function fetchDashboardStats() {
  const response = await fetch(`${API_BASE}/stats`);
  if (!response.ok) {
    throw new Error('Failed to fetch stats');
  }
  return response.json();
}

export async function fetchTestPages() {
  const response = await fetch(`${API_BASE}/test-pages`);
  if (!response.ok) {
    throw new Error('Failed to fetch test pages');
  }
  return response.json();
}

export async function fetchBenchmarkMetrics() {
  const response = await fetch(`${API_BASE}/metrics`);
  if (!response.ok) {
    throw new Error('Failed to fetch benchmark metrics');
  }
  return response.json();
}

export async function checkHealth() {
  const response = await fetch('/health');
  if (!response.ok) {
    throw new Error('Backend offline');
  }
  return response.json();
}

