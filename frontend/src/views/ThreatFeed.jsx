import ThreatBadge from '../components/ThreatBadge'
import styles from './ThreatFeed.module.css'

const LEVEL_COLORS = {
  CRITICAL: styles.critical,
  SUSPICIOUS: styles.suspicious,
  ADVISORY: styles.advisory,
  CLEAN: styles.clean,
}

function parseFinding(finding) {
  const categoryMatch = finding.match(/^([A-Z_]+)\s*\[([A-Z]+)\]/)
  const category = categoryMatch ? categoryMatch[1] : 'UNKNOWN'
  const level = categoryMatch ? categoryMatch[2] : 'CLEAN'
  return { category, level, text: finding }
}

export default function ThreatFeed({ assessment }) {
  if (!assessment) {
    return (
      <div className={styles.empty}>
        <p>No session loaded. Run a simulation to see findings.</p>
      </div>
    )
  }

  const findings = assessment.findings || []
  const assessedAt = assessment.assessed_at

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

      {findings.length === 0 ? (
        <div className={`${styles.finding} ${styles.clean}`}>
          <div className={styles.findingBar} />
          <div className={styles.findingContent}>
            <div className={styles.findingMeta}>
              <span className={`mono ${styles.findingCategory}`}>NO_FINDINGS</span>
              <ThreatBadge level="CLEAN" />
              <span className="mono text-muted">{assessedAt}</span>
            </div>
            <div className={styles.findingText}>
              All detectors returned within bounds. Session accepted.
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
                  <div className={`mono ${styles.findingText}`}>{finding}</div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      <div className={styles.identitySection}>
        <div className={styles.identityTitle}>Identity &amp; Authorization</div>
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
