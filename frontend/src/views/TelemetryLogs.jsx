import { useState, useEffect } from 'react'
import { getDatabaseSessions, getDatabaseSessionLogs } from '../api/ops'
import styles from './TelemetryLogs.module.css'

function FidelityIndicator({ value }) {
  const percentage = Math.round(value * 100)
  let fillClass = styles.fidelityFillHigh
  if (value < 0.95) {
    fillClass = styles.fidelityFillLow
  } else if (value < 0.99) {
    fillClass = styles.fidelityFillMedium
  }

  return (
    <div className={styles.fidelityBarContainer}>
      <div className={styles.fidelityTrack}>
        <div
          className={`${styles.fidelityFill} ${fillClass}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className={styles.fidelityLabel}>{value.toFixed(4)}</span>
    </div>
  )
}

export default function TelemetryLogs({ sessionResult, assessment }) {
  const [sessionsList, setSessionsList] = useState([])
  const [selectedSessionId, setSelectedSessionId] = useState('')
  const [activeSessionData, setActiveSessionData] = useState(null)
  const [telemetryLogs, setTelemetryLogs] = useState([])
  const [loading, setLoading] = useState(true)

  async function loadSessionsAndLogs() {
    setLoading(true)
    const sessionsResponse = await getDatabaseSessions(50)
    if (sessionsResponse.data && sessionsResponse.data.sessions) {
      const allSessions = sessionsResponse.data.sessions
      setSessionsList(allSessions)

      let targetSessionId = selectedSessionId
      if (!targetSessionId) {
        if (sessionResult && sessionResult.session_id) {
          targetSessionId = sessionResult.session_id
        } else if (allSessions.length > 0) {
          targetSessionId = allSessions[0].id
        }
      }

      if (targetSessionId) {
        setSelectedSessionId(targetSessionId)
        const logsResponse = await getDatabaseSessionLogs(targetSessionId)
        if (logsResponse.data) {
          setTelemetryLogs(logsResponse.data.logs || [])
          setActiveSessionData(logsResponse.data.session || null)
        }
      }
    }
    setLoading(false)
  }

  useEffect(() => {
    loadSessionsAndLogs()
  }, [sessionResult])

  async function handleSessionChange(event) {
    const newSessionId = event.target.value
    setSelectedSessionId(newSessionId)
    setLoading(true)
    const logsResponse = await getDatabaseSessionLogs(newSessionId)
    if (logsResponse.data) {
      setTelemetryLogs(logsResponse.data.logs || [])
      setActiveSessionData(logsResponse.data.session || null)
    }
    setLoading(false)
  }

  const matchCount = telemetryLogs.filter(item => item.match).length
  const mismatchCount = telemetryLogs.filter(item => !item.match).length
  const tamperCount = telemetryLogs.filter(
    item => item.expected_correction !== item.actual_correction
  ).length

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <div>
          <div className={styles.headerTitle}>Database Telemetry Logs</div>
          <div className={styles.headerSubtitle}>
            Live quantum transmission and threat detection logs queried directly from SQLite database
          </div>
        </div>

        <div className={styles.headerRight}>
          <div className={styles.dbBadge}>
            <span className={styles.dbDot} />
            <span>SQLite: qds_sentinel.db</span>
          </div>
          <button
            className={styles.refreshButton}
            onClick={loadSessionsAndLogs}
            disabled={loading}
          >
            {loading ? 'Fetching...' : 'Refresh from Database'}
          </button>
        </div>
      </div>

      <div className={styles.sessionCard}>
        <div className={styles.sessionControls}>
          <div className={styles.sessionSelectGroup}>
            <label className={styles.sessionSelectLabel}>Select Stored Session:</label>
            <select
              className={styles.sessionSelect}
              value={selectedSessionId}
              onChange={handleSessionChange}
              disabled={sessionsList.length === 0}
            >
              {sessionsList.map(s => (
                <option key={s.id} value={s.id}>
                  {s.id} ({s.verdict} · {s.threat_level})
                </option>
              ))}
            </select>
          </div>
        </div>

        {activeSessionData && (
          <div className={styles.sessionMetaRow}>
            <div className={styles.sessionMetaItem}>
              <span className={styles.sessionMetaLabel}>Session:</span>
              <span className={styles.sessionMetaValue}>{activeSessionData.id}</span>
            </div>
            <div className={styles.sessionMetaItem}>
              <span className={styles.sessionMetaLabel}>Sender:</span>
              <span className={styles.sessionMetaValue}>{activeSessionData.sender_id}</span>
            </div>
            <div className={styles.sessionMetaItem}>
              <span className={styles.sessionMetaLabel}>Recipient:</span>
              <span className={styles.sessionMetaValue}>{activeSessionData.recipient_id}</span>
            </div>
            <div className={styles.sessionMetaItem}>
              <span className={styles.sessionMetaLabel}>Verdict:</span>
              <span
                className={
                  activeSessionData.verdict === 'ACCEPT'
                    ? styles.verdictAccept
                    : styles.verdictReject
                }
              >
                {activeSessionData.verdict}
              </span>
            </div>
            {activeSessionData.attack_type && (
              <div className={styles.sessionMetaItem}>
                <span className={styles.sessionMetaLabel}>Attack:</span>
                <span className={styles.sessionMetaValue}>{activeSessionData.attack_type}</span>
              </div>
            )}
            <div className={styles.sessionMetaItem}>
              <span className={styles.sessionMetaLabel}>Message:</span>
              <span className={styles.sessionMetaValue}>"{activeSessionData.message}"</span>
            </div>
          </div>
        )}

        <div className={styles.statsBar}>
          <span className={styles.statItem}>{telemetryLogs.length} logged positions</span>
          <span className={`${styles.statItem} ${styles.statOk}`}>{matchCount} matches</span>
          {mismatchCount > 0 && (
            <span className={`${styles.statItem} ${styles.statFail}`}>
              {mismatchCount} mismatches
            </span>
          )}
          {tamperCount > 0 && (
            <span className={`${styles.statItem} ${styles.statWarn}`}>
              {tamperCount} correction tampers
            </span>
          )}
        </div>
      </div>

      {telemetryLogs.length === 0 ? (
        <div className={styles.emptyState}>
          <div className={styles.emptyTitle}>No Telemetry Logs in Database</div>
          <p className={styles.emptyMessage}>
            Run an assessment or attack simulation in the Control Panel to save and view telemetry logs here.
          </p>
        </div>
      ) : (
        <div className={styles.tableContainer}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.right}>#</th>
                <th>Pauli Basis</th>
                <th>Bell Outcome</th>
                <th>Expected Correction</th>
                <th>Actual Correction</th>
                <th>Fidelity</th>
                <th>Bit Match</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {telemetryLogs.map(log => {
                const isTampered = log.expected_correction !== log.actual_correction
                let rowClass = ''
                if (isTampered) {
                  rowClass = styles.rowTampered
                } else if (!log.match) {
                  rowClass = styles.rowMismatch
                }

                return (
                  <tr key={log.id} className={rowClass}>
                    <td className={`${styles.mono} ${styles.right}`}>{log.position_index}</td>
                    <td className={`${styles.mono} ${styles.basisCell} ${styles['basis' + log.basis]}`}>
                      {log.basis}
                    </td>
                    <td className={styles.mono}>{log.bell_outcome}</td>
                    <td className={styles.mono}>{log.expected_correction}</td>
                    <td className={styles.mono}>
                      {log.actual_correction}
                      {isTampered && <span className={styles.corrTamperWarning}> (TAMPERED)</span>}
                    </td>
                    <td>
                      <FidelityIndicator value={log.fidelity} />
                    </td>
                    <td>
                      <span className={log.match ? styles.matchOk : styles.matchFail}>
                        {log.match ? 'MATCH' : 'MISMATCH'}
                      </span>
                    </td>
                    <td className={styles.mono}>
                      {isTampered ? (
                        <span className={styles.corrTamperWarning}>TAMPERED</span>
                      ) : log.match ? (
                        <span className={styles.statOk}>NORMAL</span>
                      ) : (
                        <span className={styles.statWarn}>NOISE/ERROR</span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
