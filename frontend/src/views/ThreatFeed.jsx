import ThreatBadge from '../components/ThreatBadge'
import styles from './ThreatFeed.module.css'

const LEVEL_COLORS = {
  CRITICAL: styles.critical,
  SUSPICIOUS: styles.suspicious,
  ADVISORY: styles.advisory,
  CLEAN: styles.clean,
}

function parseFinding(finding) {
  const categoryMatch = finding.match(/^([A-Z_]+)\s*\[([A-Z]+)\]:\s*(.*)$/)
  if (!categoryMatch) {
    return {
      category: 'PROTOCOL_SECURITY',
      level: 'SUSPICIOUS',
      evidence: finding,
      impact: 'Telemetry deviates from honest baseline configuration.',
      authority: 'Layer 2 Threat Detection Policy',
    }
  }

  const category = categoryMatch[1]
  const level = categoryMatch[2]
  const evidence = categoryMatch[3]

  let impact = 'Receiver state or message digest violates deterministic verification bounds.'
  let authority = 'Deterministic protocol-integrity check'

  if (category === 'CORRECTION_TAMPERING') {
    impact = 'Receiver teleportation state no longer matches declared feedforward Pauli corrections.'
    authority = 'Deterministic Pauli correction consistency verification'
  } else if (category === 'REPLAY_ATTACK') {
    impact = 'Session fingerprint duplicate detected; packet was previously recorded in replay ledger.'
    authority = 'Deterministic session-ledger anti-replay mechanism'
  } else if (category === 'PAYLOAD_DIGEST_MISMATCH') {
    impact = 'Recomputed SHA-256 message hash does not match payload digest recorded in signature block.'
    authority = 'Authoritative SHA-256 payload integrity check'
  } else if (category === 'QBER_ANOMALY') {
    impact = 'Signature position mismatch rate exceeds statistical threshold (possible eavesdropping/forgery).'
    authority = 'Statistical hypothesis test (Amiri et al. 2016)'
  } else if (category === 'FIDELITY_ANOMALY') {
    impact = 'Teleportation fidelity dropped below acceptable quantum channel noise floor.'
    authority = 'Quantum state fidelity threshold monitor'
  }

  return { category, level, evidence, impact, authority }
}

export default function ThreatFeed({ assessment, sessionResult, attackMeta }) {
  if (!assessment) {
    return (
      <div className={styles.empty}>
        <p>No session loaded. Run a simulation to see findings.</p>
      </div>
    )
  }

  const findings = assessment.findings || []
  const assessedAt = assessment.assessed_at
  const sessionId = sessionResult?.session_id || assessment.session_id
  const message = sessionResult?.message || 'PAYLOAD_TRANSFER_AUTHENTIC_001'
  const positionsCount = sessionResult?.signature_positions?.length || assessment.qber_analysis?.total_positions || 16

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <div>
          <h2>Threat Feed</h2>
        </div>
        <div className={styles.summary}>
          <ThreatBadge level={assessment.threat_level} size="large" />
          <span className={`mono ${styles.categoryLabel}`}>{assessment.threat_category}</span>
        </div>
      </div>

      <div className={styles.sessionRail}>
        <div className={styles.railItem}>
          <span className={styles.railLabel}>SESSION ID</span>
          <span className={`mono ${styles.railValue}`}>{sessionId}</span>
        </div>
        <div className={styles.railItem}>
          <span className={styles.railLabel}>PAYLOAD MESSAGE</span>
          <span className={`mono ${styles.railValue}`}>{message}</span>
        </div>
        <div className={styles.railItem}>
          <span className={styles.railLabel}>SENDER</span>
          <span className={`mono ${styles.railValue}`}>{assessment.sender_id}</span>
        </div>
        <div className={styles.railItem}>
          <span className={styles.railLabel}>RECIPIENT</span>
          <span className={`mono ${styles.railValue}`}>{assessment.recipient_id}</span>
        </div>
        <div className={styles.railItem}>
          <span className={styles.railLabel}>SEQUENCE</span>
          <span className={`mono ${styles.railValue}`}>#{assessment.sequence_number}</span>
        </div>
        <div className={styles.railItem}>
          <span className={styles.railLabel}>POSITIONS</span>
          <span className={`mono ${styles.railValue}`}>{positionsCount} carriers</span>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className={`${styles.finding} ${styles.clean}`}>
          <div className={styles.findingBar} />
          <div className={styles.findingContent}>
            <div className={styles.findingMeta}>
              <span className={`mono ${styles.findingCategory}`}>NO_ANOMALIES_DETECTED</span>
              <ThreatBadge level="CLEAN" />
              <span className="mono text-muted">{assessedAt}</span>
            </div>
            <div className={styles.findingText}>
              All detectors returned within honest baseline bounds. Deterministic integrity and statistical hypothesis tests passed.
            </div>
          </div>
        </div>
      ) : (
        <div className={styles.feedList}>
          {findings.map((finding, index) => {
            const parsed = parseFinding(finding)
            const colorClass = LEVEL_COLORS[parsed.level] || styles.clean
            return (
              <div key={index} className={`${styles.finding} ${colorClass}`}>
                <div className={styles.findingBar} />
                <div className={styles.findingContent}>
                  <div className={styles.findingMeta}>
                    <span className={`mono ${styles.findingCategory}`}>{parsed.category}</span>
                    <ThreatBadge level={parsed.level} />
                    <span className="mono text-muted">{assessedAt}</span>
                  </div>

                  <div className={styles.structuredFindingGrid}>
                    <div className={styles.findingField}>
                      <span className={styles.fieldHeading}>OBSERVED EVIDENCE</span>
                      <span className={`mono ${styles.fieldBody}`}>{parsed.evidence}</span>
                    </div>
                    <div className={styles.findingField}>
                      <span className={styles.fieldHeading}>PROTOCOL IMPACT</span>
                      <span className={styles.fieldBody}>{parsed.impact}</span>
                    </div>
                    <div className={styles.findingField}>
                      <span className={styles.fieldHeading}>AUTHORITY</span>
                      <span className={styles.fieldBody}>{parsed.authority}</span>
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      <div className={styles.identitySection}>
        <div className={styles.identityTitle}>Identity &amp; Authorization Verification</div>
        <div className={styles.identityGrid}>
          <div>
            <span className={styles.idLabel}>actual sender</span>
            <span className="mono">{assessment.sender_id}</span>
          </div>
          <div>
            <span className={styles.idLabel}>actual recipient</span>
            <span className="mono">{assessment.recipient_id}</span>
          </div>
          <div>
            <span className={styles.idLabel}>impersonation detected</span>
            <span className={`mono ${assessment.identity_authorization?.impersonation_detected ? styles.failText : styles.okText}`}>
              {assessment.identity_authorization?.impersonation_detected ? 'YES' : 'NO'}
            </span>
          </div>
          <div>
            <span className={styles.idLabel}>unauthorized verifier</span>
            <span className={`mono ${assessment.identity_authorization?.unauthorized_verifier_detected ? styles.failText : styles.okText}`}>
              {assessment.identity_authorization?.unauthorized_verifier_detected ? 'YES' : 'NO'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
