import { useState, useEffect } from 'react'
import ControlPanel from './views/ControlPanel'
import CircuitTrace from './views/CircuitTrace'
import ThreatFeed from './views/ThreatFeed'
import MetricsPanel from './views/MetricsPanel'
import ExperimentReport from './views/ExperimentReport'
import DecisionBanner from './components/DecisionBanner'
import SimDisclaimer from './components/SimDisclaimer'
import { checkHealth, getExampleClean } from './api/client'
import { WifiOff, Activity } from 'lucide-react'
import styles from './App.module.css'

const TABS = [
  { id: 'control',    label: 'Control Panel' },
  { id: 'circuit',    label: 'Circuit Trace' },
  { id: 'feed',       label: 'Threat Feed' },
  { id: 'metrics',    label: 'Security Metrics' },
  { id: 'experiment', label: 'Experiment Report' },
]

const ATTACK_SCENARIO_LABELS = {
  REPLAY: 'Replay captured packet',
  PARTIAL_FORGERY: 'Partial signature forgery',
  CORRECTION_TAMPERING: 'Pauli correction tampering',
  FULL_FORGERY: 'Full signature forgery',
  INTERCEPT_RESEND: 'Intercept and resend',
  CHANNEL_MANIPULATION: 'Channel manipulation',
  FIDELITY_DEGRADATION: 'Fidelity degradation',
  BOB_REPUDIATION: 'Bob repudiation',
}

function ScenarioStrip({ assessment, attackMeta }) {
  if (!assessment) return null
  const isAccept = assessment.security_decision?.startsWith('ACCEPT')
  const scenarioLabel = attackMeta
    ? (ATTACK_SCENARIO_LABELS[attackMeta.attack_type] || attackMeta.attack_type)
    : 'Clean session'
  return (
    <div className={styles.scenarioStrip}>
      <span className={styles.scenarioLabel}>
        SCENARIO <span className={styles.scenarioName}>{scenarioLabel}</span>
      </span>
      <span className={styles.scenarioDivider}>|</span>
      <span className={`${styles.scenarioVerdict} ${isAccept ? styles.verdictAccept : styles.verdictReject}`}>
        VERDICT <span className={styles.verdictWord}>{isAccept ? 'ACCEPT' : 'REJECT'}</span>
      </span>
      {attackMeta && (
        <>
          <span className={styles.scenarioDivider}>|</span>
          <span className={`mono ${styles.scenarioMeta}`}>
            {attackMeta.attack_type} · q={attackMeta.intensity?.toFixed(2)}
          </span>
        </>
      )}
    </div>
  )
}

export default function App() {
  const [activeTab, setActiveTab] = useState('control')
  const [assessment, setAssessment] = useState(null)
  const [sessionResult, setSessionResult] = useState(null)
  const [attackMeta, setAttackMeta] = useState(null)
  const [backendOnline, setBackendOnline] = useState(null)

  function applyResult(result) {
    setAssessment(result.assessment ?? null)
    setSessionResult(result.sessionResult ?? null)
    setAttackMeta(result.attackMeta ?? null)
  }

  useEffect(() => {
    let mounted = true
    async function init() {
      const res = await checkHealth()
      if (mounted) {
        setBackendOnline(res.online)
      }
      if (res.online) {
        const cleanResult = await getExampleClean()
        if (mounted && cleanResult.data) {
          setAssessment(cleanResult.data.assessment)
          setSessionResult(cleanResult.data.session)
          setAttackMeta(null)
        }
      }
    }
    init()
    const interval = setInterval(async () => {
      const res = await checkHealth()
      if (mounted) setBackendOnline(res.online)
    }, 10000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  function handleResult(result) {
    applyResult(result)
    setActiveTab('feed')
  }

  const hasResult = Boolean(assessment)

  return (
    <div className={styles.shell}>
      <header className={styles.topBar}>
        <div className={styles.brand}>
          <span className={styles.brandName}>QDS Sentinel</span>
        </div>

        <div className={styles.systemStatus}>
          {backendOnline === false && (
            <div className={styles.offlineChip}>
              <WifiOff size={12} strokeWidth={1.5} />
              <span>Backend Offline (:8000)</span>
            </div>
          )}
          {backendOnline === true && !hasResult && (
            <div className={styles.onlineChip}>
              <Activity size={12} strokeWidth={1.5} />
              <span>Layer 1 &amp; Layer 2 Active</span>
            </div>
          )}
        </div>

        {hasResult && (
          <ScenarioStrip assessment={assessment} attackMeta={attackMeta} />
        )}
      </header>

      {backendOnline === false && (
        <div className={styles.backendWarning}>
          <strong>Backend Service Unreachable:</strong> Unable to connect to <code>http://localhost:8000</code>. Please start the backend server with <code>uvicorn app.main:app --reload</code>.
        </div>
      )}

      {hasResult && (
        <div className={styles.decisionBar}>
          <DecisionBanner assessment={assessment} />
        </div>
      )}

      <nav className={styles.nav}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            id={`tab-${tab.id}`}
            className={`${styles.navTab} ${activeTab === tab.id ? styles.navTabActive : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {tab.id === 'feed' && hasResult && assessment.findings?.length > 0 && (
              <span className={styles.findingCount}>{assessment.findings.length}</span>
            )}
          </button>
        ))}
      </nav>

      <main className={styles.main}>
        {activeTab === 'control' && (
          <ControlPanel onResult={handleResult} />
        )}
        {activeTab === 'circuit' && (
          <CircuitTrace sessionResult={sessionResult} assessment={assessment} />
        )}
        {activeTab === 'feed' && (
          <ThreatFeed assessment={assessment} sessionResult={sessionResult} attackMeta={attackMeta} />
        )}
        {activeTab === 'metrics' && (
          <MetricsPanel assessment={assessment} />
        )}
        {activeTab === 'experiment' && (
          <ExperimentReport />
        )}
      </main>

      {hasResult && (
        <footer className={styles.footer}>
          <SimDisclaimer text={assessment.simulation_disclaimer} />
        </footer>
      )}
    </div>
  )
}
