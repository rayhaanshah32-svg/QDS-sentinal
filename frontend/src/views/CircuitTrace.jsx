import styles from './CircuitTrace.module.css'

function FidelityBar({ value }) {
  const pct = Math.round(value * 100)
  const color = value >= 0.999 ? 'var(--color-accept-bar)' : value >= 0.95 ? 'var(--color-advisory-bar)' : 'var(--color-critical-bar)'
  return (
    <div className={styles.fidelityBar}>
      <div className={styles.fidelityFill} style={{ width: `${pct}%`, background: color }} />
      <span className={`mono ${styles.fidelityLabel}`}>{value.toFixed(4)}</span>
    </div>
  )
}

export default function CircuitTrace({ sessionResult, assessment }) {
  if (!sessionResult && !assessment) {
    return (
      <div className={styles.empty}>
        <p>Run a simulation to see per-position circuit telemetry.</p>
      </div>
    )
  }

  if (!sessionResult) {
    return (
      <div className={styles.empty}>
        <p>Circuit trace unavailable — this example was loaded from a GET endpoint that does not echo the session. Run a simulation via the Control Panel to see full telemetry.</p>
      </div>
    )
  }

  const positions = sessionResult.signature_positions || []
  const inconsistentSet = new Set(
    assessment?.correction_consistency?.inconsistent_positions || []
  )
  const lowFidelitySet = new Set(
    assessment?.fidelity_analysis?.low_fidelity_positions || []
  )

  const stats = {
    total: positions.length,
    matching: positions.filter(p => p.is_match).length,
    mismatching: positions.filter(p => !p.is_match).length,
    correctionMismatches: inconsistentSet.size,
    lowFidelity: lowFidelitySet.size,
  }

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <h2>Teleportation &amp; Circuit Trace</h2>
        <div className={styles.statsRow}>
          <span className="mono">{stats.total} positions</span>
          <span className={`mono ${styles.statOk}`}>{stats.matching} match</span>
          {stats.mismatching > 0 && (
            <span className={`mono ${styles.statFail}`}>{stats.mismatching} mismatch</span>
          )}
          {stats.correctionMismatches > 0 && (
            <span className={`mono ${styles.statWarn}`}>{stats.correctionMismatches} correction mismatch</span>
          )}
          {stats.lowFidelity > 0 && (
            <span className={`mono ${styles.statWarn}`}>{stats.lowFidelity} low-fidelity</span>
          )}
        </div>
      </div>

      <div className={styles.tableWrapper}>
        <table>
          <thead>
            <tr>
              <th className="right">#</th>
              <th>Basis</th>
              <th>Prepared State</th>
              <th>Bell Outcome</th>
              <th>Exp. Corr.</th>
              <th>Act. Corr.</th>
              <th className="right">Exp. Bit</th>
              <th className="right">Meas. Bit</th>
              <th>Fidelity</th>
              <th>Match</th>
            </tr>
          </thead>
          <tbody>
            {positions.map(pos => {
              const corrMismatch = pos.expected_correction !== pos.actual_correction
              const lowFid = lowFidelitySet.has(pos.index)
              const rowClass = corrMismatch ? styles.rowCorrMismatch : lowFid ? styles.rowLowFid : ''

              return (
                <tr key={pos.index} className={rowClass}>
                  <td className={`mono right ${styles.indexCell}`}>{pos.index}</td>
                  <td className={`mono ${styles.basisCell} ${styles[`basis${pos.pauli_basis}`]}`}>
                    {pos.pauli_basis}
                  </td>
                  <td className="mono">{pos.prepared_state_label}</td>
                  <td className="mono">{pos.bell_measurement_bits}</td>
                  <td className={`mono ${styles.corrCell}`}>{pos.expected_correction}</td>
                  <td className={`mono ${styles.corrCell} ${corrMismatch ? styles.corrMismatch : ''}`}>
                    {pos.actual_correction}
                    {corrMismatch && <span className={styles.mismatchMarker}> !</span>}
                  </td>
                  <td className="mono right">{pos.expected_bit}</td>
                  <td className={`mono right ${!pos.is_match ? styles.bitMismatch : ''}`}>
                    {pos.final_measured_bit}
                  </td>
                  <td><FidelityBar value={pos.fidelity} /></td>
                  <td>
                    <span className={pos.is_match ? styles.matchYes : styles.matchNo}>
                      {pos.is_match ? 'OK' : 'FAIL'}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
