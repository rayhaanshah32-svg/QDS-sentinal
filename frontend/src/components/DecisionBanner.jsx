import { useState } from 'react'
import { ChevronRight, ChevronDown } from 'lucide-react'
import styles from './DecisionBanner.module.css'

export default function DecisionBanner({ assessment }) {
  const [detailsOpen, setDetailsOpen] = useState(false)
  if (!assessment) return null

  const rawDecision = assessment.security_decision || ''
  const isAccept = rawDecision.startsWith('ACCEPT')
  const colorClass = isAccept ? styles.accept : styles.reject

  const mode = assessment.verification_mode?.toUpperCase() || 'DIRECT'
  const totalPositions = assessment.qber_analysis?.total_positions || 16
  const mismatchCount = Math.round((assessment.qber_analysis?.global_mismatch_rate || 0) * totalPositions)
  const mismatchRate = (assessment.qber_analysis?.global_mismatch_rate ?? 0).toFixed(4)
  const activeThreshold = mode === 'FORWARDED'
    ? `s_v = ${(assessment.s_v_used ?? 0.2).toFixed(4)}`
    : `s_a = ${(assessment.s_a_used ?? 0.1).toFixed(4)}`
  const avgFidelity = (assessment.fidelity_analysis?.average_fidelity ?? 1.0).toFixed(4)
  const fpBound = assessment.qber_analysis?.hoeffding_false_positive_bound ?? 1.0

  return (
    <div className={`${styles.banner} ${colorClass}`}>
      <div className={styles.topRow}>
        <div className={styles.verdictSection}>
          <span className={styles.verdict}>{isAccept ? 'ACCEPT' : 'REJECT'}</span>
          <span className={styles.verdictSubtitle}>
            {isAccept ? 'Packet passed deterministic protocol checks' : 'Packet failed security policy checks'}
          </span>
        </div>

        <div className={styles.fieldsGrid}>
          <div className={styles.fieldItem}>
            <span className={styles.fieldLabel}>MODE</span>
            <span className={`mono ${styles.fieldValue}`}>{mode}</span>
          </div>
          <div className={styles.fieldItem}>
            <span className={styles.fieldLabel}>OBSERVED MISMATCH</span>
            <span className={`mono ${styles.fieldValue}`}>{mismatchCount} / {totalPositions} ({mismatchRate})</span>
          </div>
          <div className={styles.fieldItem}>
            <span className={styles.fieldLabel}>THRESHOLD</span>
            <span className={`mono ${styles.fieldValue}`}>{activeThreshold}</span>
          </div>
          <div className={styles.fieldItem}>
            <span className={styles.fieldLabel}>MEAN FIDELITY</span>
            <span className={`mono ${styles.fieldValue}`}>{avgFidelity}</span>
          </div>
        </div>
      </div>

      <div className={styles.rawToggleRow}>
        <button
          type="button"
          className={styles.rawToggleButton}
          onClick={() => setDetailsOpen(!detailsOpen)}
        >
          {detailsOpen ? <ChevronDown size={12} strokeWidth={1.5} /> : <ChevronRight size={12} strokeWidth={1.5} />}
          <span>Raw engine assessment string</span>
        </button>
        {detailsOpen && (
          <div className={`mono ${styles.rawDecisionText}`}>
            {rawDecision}
          </div>
        )}
      </div>
    </div>
  )
}
