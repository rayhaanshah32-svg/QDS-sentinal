const BASE = '/api/v1'

async function request(path, options = {}) {
  try {
    const response = await fetch(BASE + path, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    })

    const text = await response.text()
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = { detail: text }
    }

    if (!response.ok) {
      return {
        data: null,
        error: {
          status: response.status,
          detail: parsed.detail || `HTTP ${response.status}`,
        },
      }
    }

    return { data: parsed, error: null }
  } catch (networkError) {
    return {
      data: null,
      error: {
        status: 0,
        detail: `Network error: ${networkError.message}. Is the backend running on port 8000?`,
      },
    }
  }
}

export async function runAssess(assessRequest) {
  return request('/layer2/assess', {
    method: 'POST',
    body: JSON.stringify(assessRequest),
  })
}

export async function runAttackSimulate(attackRequest) {
  return request('/layer2/attack-simulate', {
    method: 'POST',
    body: JSON.stringify(attackRequest),
  })
}

export async function runLayer1Simulate(simulationRequest) {
  return request('/layer1/simulate', {
    method: 'POST',
    body: JSON.stringify(simulationRequest),
  })
}

export async function getBlochState(basis, bit) {
  return request(`/layer1/bloch-state/${basis}/${bit}`)
}

export async function getBlochTrace(simulationRequest) {
  return request('/layer1/bloch-trace', {
    method: 'POST',
    body: JSON.stringify(simulationRequest),
  })
}

export async function getExampleClean() {
  return request('/layer2/example-clean')
}

export async function getExampleReplay() {
  return request('/layer2/example-replay')
}

export async function getExampleForgery() {
  return request('/layer2/example-forgery')
}

export async function checkHealth() {
  try {
    const res = await fetch('/health')
    if (res.ok) {
      const data = await res.json()
      if (data && data.status === 'ok') {
        return { online: true, data }
      }
    }
  } catch {
    // try direct fallback if proxy is cycling
  }

  try {
    const directRes = await fetch('http://127.0.0.1:8000/health')
    if (directRes.ok) {
      const directData = await directRes.json()
      if (directData && directData.status === 'ok') {
        return { online: true, data: directData }
      }
    }
    return { online: false }
  } catch (err) {
    return { online: false, error: err.message }
  }
}
