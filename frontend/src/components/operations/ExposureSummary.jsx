import styles from './operations.module.css'

const CRITICAL_TYPES = new Set([
  'CORRECTION_TAMPERING',
  'REPLAY_ATTACK',
  'PAYLOAD_DIGEST_MISMATCH',
  'IMPERSONATION',
  'UNAUTHORIZED_VERIFICATION',
  'CONFIGURATION_WARNING',
])

export default function ExposureSummary({ trendsData }) {
  const breakdown = trendsData?.threat_breakdown || []
  const totalEvents = breakdown.reduce((sum, item) => sum + (item.count || 0), 0)

  const topThree = breakdown.slice(0, 3)
  const topIssue = topThree.length > 0 ? topThree[0] : null

  return (
    <div className={styles.sectionBlock}>
      <div className={styles.sectionHeader}>
        <div>
          <h2 className={styles.sectionTitle}>How exposed am I</h2>
          <p className={styles.sectionSubtitle}>Breakdown of vulnerabilities and repeat attack patterns</p>
        </div>
      </div>

      <div className={styles.exposureCard}>
        <div className={styles.exposureTopSummary}>
          <span className={styles.exposureSummaryLabel}>Vulnerability focus:</span>
          <span className={styles.exposureSummaryText}>
            {topIssue ? (
              <>
                Most common issue is{' '}
                <strong className={styles.exposureHighlight}>
                  {topIssue.type.toLowerCase()}
                </strong>{' '}
                ({topIssue.count} {topIssue.count === 1 ? 'time' : 'times'} this week)
              </>
            ) : (
              'None — no repeat issues or security vulnerabilities detected.'
            )}
          </span>
        </div>

        {topThree.length > 0 && (
          <div className={styles.exposureRankedList}>
            {topThree.map((item, index) => {
              const isCritical = CRITICAL_TYPES.has(item.raw_type)
              const percentage = totalEvents > 0 ? Math.round((item.count / totalEvents) * 100) : 0
              const barClass = isCritical ? styles.exposureBarCritical : styles.exposureBarSuspicious

              return (
                <div key={item.raw_type || index} className={styles.exposureItem}>
                  <div className={styles.exposureItemHeader}>
                    <div className={styles.exposureItemLeft}>
                      <span className={styles.exposureRank}>#{index + 1}</span>
                      <span className={styles.exposureItemName}>{item.type}</span>
                    </div>
                    <span className={styles.exposureItemStats}>
                      <strong>{item.count}</strong> {item.count === 1 ? 'incident' : 'incidents'} ({percentage}%)
                    </span>
                  </div>

                  <div className={styles.exposureTrack}>
                    <div
                      className={`${styles.exposureBar} ${barClass}`}
                      style={{ width: `${Math.max(percentage, 6)}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
