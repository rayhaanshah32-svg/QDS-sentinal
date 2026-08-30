import styles from './ThreatBadge.module.css'

const LEVEL_META = {
  CLEAN: { label: 'CLEAN', color: 'accept' },
  ADVISORY: { label: 'ADVISORY', color: 'advisory' },
  SUSPICIOUS: { label: 'SUSPICIOUS', color: 'suspicious' },
  CRITICAL: { label: 'CRITICAL', color: 'critical' },
}

export default function ThreatBadge({ level, size = 'normal' }) {
  const meta = LEVEL_META[level] || { label: level, color: 'neutral' }
  return (
    <span className={`${styles.badge} ${styles[meta.color]} ${size === 'large' ? styles.large : ''}`}>
      {meta.label}
    </span>
  )
}
