import { useState, useEffect } from 'react'
import ControlPanel from './views/ControlPanel'
import CircuitTrace from './views/CircuitTrace'
import ThreatFeed from './views/ThreatFeed'
import MetricsPanel from './views/MetricsPanel'
import ExperimentReport from './views/ExperimentReport'
import DecisionBanner from './components/DecisionBanner'
import ThreatBadge from './components/ThreatBadge'
import SimDisclaimer from './components/SimDisclaimer'
import { checkHealth, getExampleClean, runLayer1Simulate } from './api/client'
import { WifiOff, Activity } from 'lucide-react'
import styles from './App.module.css'

const TABS = [
  { id: 'control',    label: 'Control Panel' },
  { id: 'circuit',    label: 'Circuit Trace' },
  { id: 'feed',       label: 'Threat Feed' },
  { id: 'metrics',    label: 'Security Metrics' },
  { id: 'experiment', label: 'Experiment Report' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('control')
  const [assessment, setAssessment] = useState(null)
  const [sessionResult, setSessionResult] = useState(null)
  const [attackMeta, setAttackMeta] = useState(null)
  const [backendOnline, setBackendOnline] = useState(null)

  useEffect(() => {
    let mounted = true
    async function init() {
      const res = await checkHealth()
      if (mounted) {
        setBackendOnline(res.online)
      }
      if (res.online) {
        const [cleanAssess, cleanSession] = await Promise.all([
          getExampleClean(),
          runLayer1Simulate({
            message: 'AUTHENTICATED_TRANSACTION_PAYLOAD_CLEAN',
            sender_id: 'alice',
            recipient_id: 'bob',
            signature_length: 16,
            seed: 42,
            bell_state: 'PHI_PLUS',
            bases_allowed: ['X', 'Y', 'Z'],
            sequence_number: 1,
          }),
        ])
        if (mounted && cleanAssess.data && cleanSession.data) {
          setAssessment(cleanAssess.data)
          setSessionResult(cleanSession.data)
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
    setAssessment(result.assessment)
    setSessionResult(result.sessionResult)
    setAttackMeta(result.attackMeta)
    setActiveTab('feed')
  }

  const threatLevel = assessment?.threat_level
  const hasResult = Boolean(assessment)

  return (
    <div className={styles.shell}>
      <header className={styles.topBar}>
        <div className={styles.brand}>
          <span className={styles.brandName}>QDS Sentinel</span>
          <span className={styles.brandLayer}>Layer 3 — Security Dashboard</span>
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
          <div className={styles.statusStrip}>
            <ThreatBadge level={threatLevel} />
          </div>
        )}

        {attackMeta && (
          <div className={styles.attackStrip}>
            <span className={`mono ${styles.attackLabel}`}>ATTACK</span>
            <span className="mono" style={{ fontSize: 10 }}>
              {attackMeta.attack_type} · q={attackMeta.intensity.toFixed(2)} · {attackMeta.description}
            </span>
          </div>
        )}
      </header>

      {backendOnline === false && (
        <div className={styles.backendWarning}>
          <strong>Backend Service Unreachable:</strong> Unable to connect to <code>http://localhost:8000</code>. Please start the backend server with <code>uvicorn app.main:app --reload</code>.
        </div>
      )}

      {hasResult && (
        <div className={styles.decisionBar}>
          <DecisionBanner
            securityDecision={assessment.security_decision}
            threatLevel={assessment.threat_level}
          />
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
          <ThreatFeed assessment={assessment} />
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
