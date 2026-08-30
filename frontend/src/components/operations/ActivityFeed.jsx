import styles from './operations.module.css'

const REAL_WORLD_CONSEQUENCES = {
  CORRECTION_TAMPERING: 'A message was altered in transit. Do not trust this payload.',
  BELL_INTEGRITY_VIOLATION: 'Someone may be intercepting or disrupting the quantum link.',
  QBER_ANOMALY: 'Higher error rate than normal. Indicates active eavesdropping.',
  REPLAY_ATTACK: 'An attacker tried to resend a captured old message.',
  PAYLOAD_DIGEST_MISMATCH: 'The message body was modified after the signature was created.',
  IMPERSONATION: 'The claimed sender or recipient identity failed verification.',
  UNAUTHORIZED_VERIFICATION: 'An unauthorized third party attempted to read this message.',
  BOB_THRESHOLD_BREACH: 'Direct recipient verification failed security safety limits.',
  CHARLIE_THRESHOLD_BREACH: 'Forwarded recipient verification failed security safety limits.',
  CONFIGURATION_WARNING: 'Cryptographic parameter configuration is invalid.',
}

function formatTimestamp(isoString) {
  if (!isoString) return ''
  const date = new Date(isoString)
  if (isNaN(date.getTime())) return ''
  const now = new Date()
  const diffMs = now - date
  const diffMins = Math.floor(diffMs / 60000)
  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  return date.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function EventCard({ event }) {
  const isCritical = event.severity === 'critical'
  const cardBorderClass = isCritical ? styles.eventCardCritical : styles.eventCardSuspicious
  const tagClass = isCritical ? styles.eventTagCritical : styles.eventTagSuspicious
  const consequence = REAL_WORLD_CONSEQUENCES[event.threat_type] || event.detail || 'Channel anomaly detected.'

  return (
    <li className={`${styles.eventCard} ${cardBorderClass}`}>
      <div className={styles.eventHeader}>
        <div className={styles.eventHeaderLeft}>
          <span className={`${styles.eventTag} ${tagClass}`}>
            {isCritical ? 'CRITICAL THREAT' : 'SUSPICIOUS'}
          </span>
          <span className={styles.eventHeadline}>{event.headline}</span>
        </div>
        <span className={styles.eventTimestamp}>{formatTimestamp(event.timestamp)}</span>
      </div>

      <div className={styles.eventSentence}>{event.sentence}</div>

      <div className={styles.eventConsequence}>
        <span className={styles.eventConsequenceLabel}>WHAT THIS MEANS:</span> {consequence}
      </div>
    </li>
  )
}

export default function ActivityFeed({ feedData }) {
  const events = feedData?.events || []

  return (
    <div className={styles.sectionBlock}>
      <div className={styles.sectionHeader}>
        <div>
          <h2 className={styles.sectionTitle}>What happened</h2>
          <p className={styles.sectionSubtitle}>Recent security flags and their real-world impact</p>
        </div>
        <span className={styles.sectionCount}>
          {events.length > 0 ? `${events.length} flagged event${events.length !== 1 ? 's' : ''}` : '0 flags'}
        </span>
      </div>

      {events.length === 0 ? (
        <div className={styles.emptyCard}>
          <div className={styles.emptyHeading}>All clear</div>
          <p className={styles.emptyText}>No suspicious events or security violations recorded today.</p>
        </div>
      ) : (
        <ul className={styles.eventList}>
          {events.map(event => (
            <EventCard key={event.id} event={event} />
          ))}
        </ul>
      )}
    </div>
  )
}
