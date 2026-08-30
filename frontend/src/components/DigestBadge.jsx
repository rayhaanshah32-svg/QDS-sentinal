import { CheckCircle, XCircle } from 'lucide-react'
import styles from './DeterministicBadge.module.css'

export default function DigestBadge({ digestCheck }) {
  if (!digestCheck) return null
  const ok = digestCheck.digest_matches

  return (
    <div className={`${styles.badge} ${ok ? styles.ok : styles.fail}`}>
      <div className={styles.icon}>
        {ok
          ? <CheckCircle size={14} strokeWidth={1.5} />
          : <XCircle size={14} strokeWidth={1.5} />
        }
      </div>
      <div className={styles.content}>
        <span className={styles.label}>PAYLOAD DIGEST CONSISTENCY</span>
        <span className={styles.status}>{ok ? 'MATCH (VERIFIED)' : 'MISMATCH — AUTHORITATIVE REJECT'}</span>
        {!ok && (
          <div className={styles.hashes}>
            <div className="mono">
              <span className={styles.hashLabel}>recorded: </span>
              {digestCheck.recorded_digest}
            </div>
            <div className="mono">
              <span className={styles.hashLabel}>recomputed: </span>
              {digestCheck.recomputed_digest}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
