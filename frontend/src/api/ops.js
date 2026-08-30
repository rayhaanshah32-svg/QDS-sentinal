const BASE = '/api/ops'

async function opsRequest(path) {
  try {
    const response = await fetch(BASE + path, {
      headers: { 'Content-Type': 'application/json' },
    })
    const text = await response.text()
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = { detail: text }
    }
    if (!response.ok) {
      return { data: null, error: { status: response.status, detail: parsed.detail || `HTTP ${response.status}` } }
    }
    return { data: parsed, error: null }
  } catch (networkError) {
    return { data: null, error: { status: 0, detail: `Network error: ${networkError.message}` } }
  }
}

export async function getOpsOverview() {
  return opsRequest('/overview')
}

export async function getOpsThreatFeed() {
  return opsRequest('/threat-feed')
}

export async function getOpsTrends() {
  return opsRequest('/trends')
}

export async function getDatabaseSessions(limit = 50) {
  return opsRequest(`/sessions?limit=${limit}`)
}

export async function getDatabaseSessionLogs(sessionId) {
  return opsRequest(`/logs/${sessionId}`)
}

export async function getRecentDatabaseLogs(limit = 100) {
  return opsRequest(`/logs?limit=${limit}`)
}

