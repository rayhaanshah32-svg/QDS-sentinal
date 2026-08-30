import DigestBadge from '../components/DigestBadge'
import ReplayBadge from '../components/ReplayBadge'
import styles from './MetricsPanel.module.css'

function MetricRow({ label, value, unit = '', flagged = false, mono = true }) {
  return (
    <div className={styles.metricRow}>
      <span className={styles.metricLabel}>{label}</span>
      <span className={`${styles.metricValue} ${mono ? 'mono' : ''} ${flagged ? styles.flagged : ''}`}>
        {value}{unit ? <span className={styles.unit}>{unit}</span> : null}
      </span>
    </div>
  )
}

function FlagIndicator({ raised }) {
  return (
    <span className={`${styles.flag} ${raised ? styles.flagRaised : styles.flagClear}`}>
      {raised ? 'FLAGGED' : 'CLEAR'}
    </span>
  )
}

export default function MetricsPanel({ assessment }) {
  if (!assessment) {
    return (
      <div className={styles.empty}>
        <p>Run a simulation to see security metrics.</p>
      </div>
    )
  }

  const qber = assessment.qber_analysis
  const corr = assessment.correction_consistency
  const fid = assessment.fidelity_analysis
  const bc = assessment.bob_charlie_metrics

  return (
    <div className={styles.root}>
      <h2>Security Metrics</h2>

      <div className={styles.deterministicRow}>
        <DigestBadge digestCheck={assessment.digest_check} />
        <ReplayBadge replayDetection={assessment.replay_detection} />
      </div>

      <div className={styles.thresholdsRow}>
        <div className={styles.thresholdChip}>
          <span className={styles.chipLabel}>s_a used</span>
          <span className="mono">{assessment.s_a_used}</span>
        </div>
        <div className={styles.thresholdChip}>
          <span className={styles.chipLabel}>s_v used</span>
          <span className="mono">{assessment.s_v_used}</span>
        </div>
        <div className={styles.thresholdChip}>
          <span className={styles.chipLabel}>p_E used</span>
          <span className="mono">{assessment.p_E_used}</span>
        </div>
        <div className={styles.thresholdChip}>
          <span className={styles.chipLabel}>e_honest used</span>
          <span className="mono">{assessment.e_honest_used}</span>
        </div>
        <div className={styles.thresholdChip}>
          <span className={styles.chipLabel}>mode</span>
          <span className="mono">{assessment.verification_mode}</span>
        </div>
      </div>

      <div className={styles.panelsGrid}>
        <div className={`panel ${styles.metricPanel}`}>
          <div className={`panel-title ${styles.panelTitleRow}`}>
            Signature Mismatch Rate
            <FlagIndicator raised={qber.exceeds_threshold} />
          </div>
          <div className={styles.disclaimerNote}>
            Calculated from simulated signature telemetry, not direct physical-channel QBER measurements.
          </div>
          <MetricRow label="observed_mismatch_rate" value={qber.global_mismatch_rate.toFixed(4)} flagged={qber.exceeds_threshold} />
          <MetricRow label="alert_threshold (q_alert)" value={qber.alert_threshold.toFixed(4)} />
          <MetricRow label="total_positions" value={qber.total_positions} />
          <MetricRow label="hoeffding_fp_bound" value={qber.hoeffding_false_positive_bound.toFixed(6)} />
          <div className={styles.basisTable}>
            <div className={styles.basisHeader}>
              <span>Basis</span>
              <span className="right">Samples</span>
              <span className="right">Mismatches</span>
              <span className="right">Rate</span>
            </div>
            {[qber.qber_x, qber.qber_y, qber.qber_z].map(b => (
              <div key={b.basis} className={styles.basisRow}>
                <span className={`mono ${styles[`basis${b.basis}`]}`}>{b.basis}</span>
                <span className="mono right">{b.sample_count}</span>
                <span className="mono right">{b.mismatch_count}</span>
                <span className={`mono right ${b.rate > qber.alert_threshold ? styles.flagged : ''}`}>
                  {b.rate.toFixed(4)}
                  {b.insufficient_samples && <span className={styles.insuf}> insuf.</span>}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className={`panel ${styles.metricPanel}`}>
          <div className={`panel-title ${styles.panelTitleRow}`}>
            Pauli Correction Consistency
            <FlagIndicator raised={corr.flag_raised} />
          </div>
          <div className={styles.disclaimerNote}>
            Feedforward Pauli correction integrity across classical transmission.
          </div>
          <MetricRow label="inconsistency_rate" value={corr.inconsistency_rate.toFixed(4)} flagged={corr.flag_raised} />
          <MetricRow label="tamper_threshold" value={corr.tamper_threshold.toFixed(4)} />
          <MetricRow label="inconsistency_count" value={corr.inconsistency_count} />
          <div className={styles.positionList}>
            <span className={styles.metricLabel}>inconsistent_positions</span>
            {corr.inconsistent_positions.length === 0 ? (
              <span className={`mono ${styles.okText}`}>none</span>
            ) : (
              <span className={`mono ${styles.flagged}`}>[{corr.inconsistent_positions.join(', ')}]</span>
            )}
          </div>
        </div>

        <div className={`panel ${styles.metricPanel}`}>
          <div className={`panel-title ${styles.panelTitleRow}`}>
            Teleportation Fidelity Monitor
            <FlagIndicator raised={fid.flag_raised} />
          </div>
          <div className={styles.disclaimerNote}>
            Simulated state reconstruction fidelity across all teleported carriers.
          </div>
          <MetricRow label="average_fidelity" value={fid.average_fidelity.toFixed(4)} />
          <MetricRow label="min_fidelity" value={fid.min_fidelity.toFixed(4)} flagged={fid.flag_raised} />
          <MetricRow label="fidelity_floor" value={fid.fidelity_floor.toFixed(4)} />
          <div className={styles.positionList}>
            <span className={styles.metricLabel}>low_fidelity_positions</span>
            {fid.low_fidelity_positions.length === 0 ? (
              <span className={`mono ${styles.okText}`}>none</span>
            ) : (
              <span className={`mono ${styles.flagged}`}>[{fid.low_fidelity_positions.join(', ')}]</span>
            )}
          </div>
        </div>
      </div>

      <div className={`panel ${styles.bcPanel}`}>
        <div className={`panel-title ${styles.panelTitleRow}`}>
          Bob / Charlie Mismatch Metrics (Isolated Channels)
          <span className={styles.splitNote}>split: {bc.splitting_method}</span>
        </div>
        <div className={styles.bcColumns}>
          <div className={`${styles.bcColumn} ${bc.direct_exceeds_threshold ? styles.bcColumnFlagged : ''}`}>
            <div className={styles.bcColumnHeader}>
              <span>Bob (direct authentication)</span>
              <FlagIndicator raised={bc.direct_exceeds_threshold} />
            </div>
            <MetricRow label="positions" value={bc.direct_positions_count} />
            <MetricRow label="mismatches" value={bc.direct_mismatch_count} />
            <MetricRow
              label="mismatch_rate"
              value={bc.direct_mismatch_rate.toFixed(4)}
              flagged={bc.direct_exceeds_threshold}
            />
            <MetricRow
              label="threshold (s_a)"
              value={bc.direct_threshold_s_a.toFixed(4)}
            />
            <MetricRow
              label="confidence_upper_bound"
              value={`${bc.direct_confidence_upper_bound.toFixed(4)} (uncertainty)`}
            />
            <MetricRow label="e_upper" value={bc.direct_e_upper.toFixed(4)} />
          </div>

          <div className={styles.bcDivider} />

          <div className={`${styles.bcColumn} ${bc.forwarded_exceeds_threshold ? styles.bcColumnFlagged : ''}`}>
            <div className={styles.bcColumnHeader}>
              <span>Charlie (forwarded verification)</span>
              <FlagIndicator raised={bc.forwarded_exceeds_threshold} />
            </div>
            <MetricRow label="positions" value={bc.forwarded_positions_count} />
            <MetricRow label="mismatches" value={bc.forwarded_mismatch_count} />
            <MetricRow
              label="mismatch_rate"
              value={bc.forwarded_mismatch_rate.toFixed(4)}
              flagged={bc.forwarded_exceeds_threshold}
            />
            <MetricRow
              label="threshold (s_v)"
              value={bc.forwarded_threshold_s_v.toFixed(4)}
            />
            <MetricRow
              label="confidence_upper_bound"
              value={`${bc.forwarded_confidence_upper_bound.toFixed(4)} (uncertainty)`}
            />
            <MetricRow label="e_upper" value={bc.forwarded_e_upper.toFixed(4)} />
          </div>
        </div>
      </div>
    </div>
  )
}
