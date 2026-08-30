import { CheckCircle, AlertTriangle } from 'lucide-react'
import styles from './DeterministicBadge.module.css'

export default function ReplayBadge({ replayDetection }) {
  if (!replayDetection) return null
  const isReplay = replayDetection.is_replay

  return (
    <div className={`${styles.badge} ${isReplay ? styles.fail : styles.ok}`}>
      <div className={styles.icon}>
        {isReplay
          ? <AlertTriangle size={14} strokeWidth={1.5} />
          : <CheckCircle size={14} strokeWidth={1.5} />
        }
      </div>
      <div className={styles.content}>
        <span className={styles.label}>Replay Detection</span>
        <span className={styles.status}>
          {isReplay ? 'REPLAY DETECTED — AUTHORITATIVE REJECT' : 'UNIQUE — no prior record'}
        </span>
        <div className={styles.hashes}>
          <div className="mono">
            <span className={styles.hashLabel}>fingerprint: </span>
            {replayDetection.fingerprint}
          </div>
          <div className="mono">
            <span className={styles.hashLabel}>ledger_size: </span>
            {replayDetection.ledger_size}
          </div>
        </div>
      </div>
    </div>
  )
}
