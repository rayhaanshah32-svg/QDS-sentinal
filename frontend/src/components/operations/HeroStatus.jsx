import styles from './operations.module.css'

function getStatusConfig(status) {
  switch (status) {
    case 'critical':
      return {
        word: 'UNDER ATTACK',
        cssClass: styles.heroCritical,
        badgeClass: styles.heroBadgeCritical,
        accentClass: styles.heroAccentCritical,
        colorType: 'critical',
      }
    case 'suspicious':
    case 'advisory':
      return {
        word: 'SOMETHING LOOKS OFF',
        cssClass: styles.heroSuspicious,
        badgeClass: styles.heroBadgeSuspicious,
        accentClass: styles.heroAccentSuspicious,
        colorType: 'suspicious',
      }
    case 'clean':
    default:
      return {
        word: 'SAFE',
        cssClass: styles.heroClean,
        badgeClass: styles.heroBadgeClean,
        accentClass: styles.heroAccentClean,
        colorType: 'clean',
      }
  }
}

function computePlainSentence(status, sessions, threats) {
  const total = sessions?.total ?? 0
  const rejected = sessions?.rejected ?? 0
  const criticalCount = threats?.critical ?? 0
  const suspiciousCount = threats?.suspicious ?? 0

  if (total === 0) {
    return 'No messages have been evaluated today. System is ready to verify incoming traffic.'
  }

  if (status === 'critical') {
    if (rejected > 0) {
      return `${rejected} of ${total} message${total === 1 ? '' : 's'} checked today failed quantum security checks and were rejected.`
    }
    return `${criticalCount} critical threat${criticalCount === 1 ? '' : 's'} detected in today's traffic. Immediate attention recommended.`
  }

  if (status === 'suspicious' || status === 'advisory') {
    if (rejected > 0) {
      return `${rejected} of ${total} message${total === 1 ? '' : 's'} checked today showed channel anomalies and were flagged.`
    }
    return `${suspiciousCount} suspicious event${suspiciousCount === 1 ? '' : 's'} detected in today's transmission channel.`
  }

  return `All ${total} message${total === 1 ? '' : 's'} checked today passed all quantum security checks.`
}

function formatRelativeTime(isoString) {
  if (!isoString) return null
  const date = new Date(isoString)
  if (isNaN(date.getTime())) return null
  const now = new Date()
  const diffMs = now - date
  const diffMins = Math.floor(diffMs / 60000)
  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  return date.toLocaleDateString()
}

export default function HeroStatus({ overview }) {
  if (!overview) {
    return (
      <div className={styles.heroPanel}>
        <div className={styles.heroMain}>
          <div className={styles.heroKicker}>SYSTEM STATUS</div>
          <div className={`${styles.heroStatusWord} ${styles.heroClean}`}>SAFE</div>
          <div className={styles.heroSentence}>
            No traffic recorded yet — run an assessment to see live risk status here.
          </div>
        </div>
      </div>
    )
  }

  const rawStatus = overview.current_status || 'clean'
  const config = getStatusConfig(rawStatus)
  const sessions = overview.sessions_24h || { total: 0, rejected: 0, accepted: 0 }
  const threats = overview.threat_counts_24h || { critical: 0, suspicious: 0, total_threats: 0 }
  const lastAssessed = formatRelativeTime(overview.last_assessed_at)

  const totalSessions = sessions.total || 0
  const rejectedSessions = sessions.rejected || 0
  const threatRate = totalSessions > 0
    ? Math.round((rejectedSessions / totalSessions) * 100)
    : 0

  const plainSentence = computePlainSentence(rawStatus, sessions, threats)

  return (
    <div className={`${styles.heroPanel} ${config.accentClass}`}>
      <div className={styles.heroContentGrid}>
        <div className={styles.heroPrimary}>
          <div className={styles.heroKicker}>
            CURRENT THREAT STATUS
            {lastAssessed && (
              <span className={styles.heroLastChecked}>
                Last checked {lastAssessed}
                {overview.last_verdict && ` · Verdict: ${overview.last_verdict}`}
              </span>
            )}
          </div>
          <h1 className={`${styles.heroStatusWord} ${config.cssClass}`}>
            {config.word}
          </h1>
          <p className={styles.heroSentence}>{plainSentence}</p>
        </div>

        <div className={styles.heroRateBox}>
          <div className={styles.heroRateNumber}>
            {totalSessions > 0 ? `${threatRate}%` : '0%'}
          </div>
          <div className={styles.heroRateLabel}>
            {totalSessions > 0 ? "of today's traffic was flagged" : 'no traffic checked today'}
          </div>
          <div className={styles.heroRateSub}>
            {rejectedSessions} rejected / {totalSessions} total
          </div>
        </div>
      </div>
    </div>
  )
}
