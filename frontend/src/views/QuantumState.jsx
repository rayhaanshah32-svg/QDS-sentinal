import { useState, useEffect, useMemo } from 'react'
import BlochSphere from '../components/BlochSphere'
import ErrorBanner from '../components/ErrorBanner'
import { getBlochTrace } from '../api/client'
import { ChevronLeft, ChevronRight, Activity, ShieldCheck, ShieldAlert } from 'lucide-react'
import styles from './QuantumState.module.css'

function FidelityBar({ value }) {
  const pct = Math.round((value ?? 1) * 100)
  const color =
    value >= 0.999
      ? 'var(--color-accept-bar)'
      : value >= 0.95
      ? 'var(--color-advisory-bar)'
      : 'var(--color-critical-bar)'
  return (
    <div className={styles.fidelityBar}>
      <div className={styles.fidelityFill} style={{ width: `${pct}%`, background: color }} />
      <span className={`mono ${styles.fidelityLabel}`}>{(value ?? 1).toFixed(4)}</span>
    </div>
  )
}

export default function QuantumState({ sessionResult, assessment, initialPosition = null }) {
  const [selectedIndex, setSelectedIndex] = useState(initialPosition ?? 0)
  const [blochTrace, setBlochTrace] = useState([])
  const [loading, setLoading] = useState(false)
  const [fetchError, setFetchError] = useState(null)

  const positions = useMemo(() => sessionResult?.signature_positions || [], [sessionResult])

  useEffect(() => {
    if (initialPosition !== null && initialPosition !== undefined) {
      setSelectedIndex(initialPosition)
    }
  }, [initialPosition])

  useEffect(() => {
    if (!sessionResult) {
      setBlochTrace([])
      return
    }

    let isMounted = true
    async function fetchTrace() {
      setLoading(true)
      setFetchError(null)

      const config = sessionResult.configuration || {}
      const payload = {
        message: sessionResult.message || 'AUTHENTICATED_TRANSACTION_PAYLOAD_001',
        sender_id: sessionResult.sender_id || 'alice',
        recipient_id: sessionResult.recipient_id || 'bob',
        signature_length: positions.length || 16,
        seed: config.seed ?? 42,
        bell_state: config.bell_state || 'PHI_PLUS',
        bases_allowed: config.bases_allowed || ['X', 'Y', 'Z'],
        session_id: sessionResult.session_id,
        nonce: sessionResult.nonce,
        sequence_number: sessionResult.sequence_number || 1,
      }

      const res = await getBlochTrace(payload)
      if (isMounted) {
        if (res.data) {
          setBlochTrace(res.data)
        } else if (res.error) {
          setFetchError(res.error)
        }
        setLoading(false)
      }
    }

    fetchTrace()
    return () => {
      isMounted = false
    }
  }, [sessionResult, positions.length])

  // Clamp index if signature length changes
  useEffect(() => {
    if (selectedIndex >= positions.length && positions.length > 0) {
      setSelectedIndex(0)
    }
  }, [positions.length, selectedIndex])

  if (!sessionResult && !assessment) {
    return (
      <div className={styles.empty}>
        <p>Run a simulation to inspect quantum state Bloch sphere telemetry.</p>
      </div>
    )
  }

  if (!sessionResult) {
    return (
      <div className={styles.empty}>
        <p>Quantum state telemetry unavailable — run a simulation via the Control Panel to see full state vectors.</p>
      </div>
    )
  }

  const currentPos = positions[selectedIndex] || positions[0]
  const currentBloch = blochTrace[selectedIndex] || null

  // Fallback / analytical calculation if trace is still loading or backend is offline
  const currentCoords = currentBloch?.coordinates || {
    x: currentPos?.pauli_basis === 'X' ? (currentPos.encoded_bit === 0 ? 1 : -1) : 0,
    y: currentPos?.pauli_basis === 'Y' ? (currentPos.encoded_bit === 0 ? 1 : -1) : 0,
    z: currentPos?.pauli_basis === 'Z' ? (currentPos.encoded_bit === 0 ? 1 : -1) : 0,
  }

  const isCollapsed = currentBloch
    ? currentBloch.is_collapsed
    : currentPos?.pauli_basis !== 'Z' || !currentPos?.is_match

  const collapsedCoords = currentBloch?.collapsed_coordinates || (isCollapsed ? {
    x: 0,
    y: 0,
    z: currentPos?.final_measured_bit === 0 ? 1 : -1,
  } : null)

  const handlePrev = () => setSelectedIndex((prev) => Math.max(0, prev - 1))
  const handleNext = () => setSelectedIndex((prev) => Math.min(positions.length - 1, prev + 1))

  return (
    <div className={styles.root}>
      {/* Error Banner */}
      {fetchError && (
        <ErrorBanner error={fetchError} />
      )}

      {/* Header Bar */}
      <div className={styles.header}>
        <div>
          <h2>Bloch Sphere &amp; Statevector Telemetry</h2>
          <span className={styles.subtitle}>
            Analytical 3D state vector projection &amp; measurement collapse verification
          </span>
        </div>

        {/* Position Step Selector */}
        <div className={styles.stepperContainer}>
          <button
            type="button"
            className={styles.stepBtn}
            onClick={handlePrev}
            disabled={selectedIndex <= 0}
            title="Previous signature position"
          >
            <ChevronLeft size={16} strokeWidth={1.5} />
          </button>

          <div className={styles.positionDisplay}>
            <span className="mono">
              Position <span className={styles.posCurrent}>{selectedIndex}</span> / {positions.length - 1}
            </span>
          </div>

          <button
            type="button"
            className={styles.stepBtn}
            onClick={handleNext}
            disabled={selectedIndex >= positions.length - 1}
            title="Next signature position"
          >
            <ChevronRight size={16} strokeWidth={1.5} />
          </button>
        </div>
      </div>

      {/* Main Grid: 3D Visualization + Telemetry Sidebar */}
      <div className={styles.grid}>
        {/* Left Column: 3D Bloch Sphere Panel */}
        <div className={styles.spherePanel}>
          <div className={styles.sphereHeader}>
            <span className={styles.panelTitle}>
              Qubit Statevector Visualizer
            </span>
            <div className={styles.legend}>
              <span className={styles.legendItem}>
                <span className={`${styles.dot} ${styles.dotAccept}`} /> Prepared State
              </span>
              <span className={styles.legendItem}>
                <span className={`${styles.dot} ${styles.dotCritical}`} /> Collapsed / Measurement
              </span>
            </div>
          </div>

          {loading ? (
            <div className={`${styles.skeletonCanvas} pulse`}>
              <Activity size={18} strokeWidth={1.5} />
              <span className="mono text-muted text-small">Computing Bloch statevectors...</span>
            </div>
          ) : (
            <BlochSphere
              coordinates={currentCoords}
              collapsedCoordinates={collapsedCoords}
              isCollapsed={isCollapsed}
              label={currentPos?.prepared_state_label || '|Ψ⟩'}
            />
          )}

          <div className={styles.sphereFooter}>
            <span className="mono text-muted">
              Vector: x={currentCoords.x?.toFixed(4)}, y={currentCoords.y?.toFixed(4)}, z={currentCoords.z?.toFixed(4)}
            </span>
            <span className={styles.hintText}>
              Click &amp; drag sphere to orbit view
            </span>
          </div>
        </div>

        {/* Right Column: Detailed Position Telemetry */}
        <div className={styles.sidebarPanel}>
          <span className={styles.panelTitle}>
            Position Telemetry Details
          </span>

          <div className={styles.metricList}>
            {loading ? (
              <>
                <div className={`${styles.skeletonBadge} pulse`} />
                <div className={`${styles.skeletonRow} pulse`} />
                <div className={`${styles.skeletonRow} pulse`} />
                <div className={`${styles.skeletonRow} pulse`} />
                <div className={`${styles.skeletonRow} pulse`} />
                <div className={`${styles.skeletonRow} pulse`} />
                <div className={`${styles.skeletonRow} pulse`} />
              </>
            ) : (
              <>
                {/* Status Card */}
                <div className={`${styles.statusCard} ${currentPos?.is_match ? styles.statusOk : styles.statusFail}`}>
                  <div className={styles.statusHeader}>
                    {currentPos?.is_match ? (
                      <ShieldCheck size={16} strokeWidth={1.5} className={styles.iconOk} />
                    ) : (
                      <ShieldAlert size={16} strokeWidth={1.5} className={styles.iconFail} />
                    )}
                    <span className={styles.statusTitle}>
                      {currentPos?.is_match ? 'Signature Element Valid' : 'Bit Mismatch / Altered State'}
                    </span>
                  </div>
                  <span className={styles.statusDesc}>
                    {currentPos?.is_match
                      ? 'Decoded bit matches prepared eigenstate perfectly.'
                      : 'Teleported state measurement yielded discrepancy (Layer 2 alertable).'}
                  </span>
                </div>

                {/* Metrics Breakdown Rows */}
                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Prepared State</span>
                  <span className="mono font-semibold">{currentPos?.prepared_state_label}</span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Preparation Basis</span>
                  <span className={`mono font-semibold ${styles[`basis${currentPos?.pauli_basis}`]}`}>
                    Pauli-{currentPos?.pauli_basis}
                  </span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Prepared Bit</span>
                  <span className="mono">{currentPos?.encoded_bit}</span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Bell Channel State</span>
                  <span className="mono">{currentPos?.bell_state || 'PHI_PLUS'}</span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Bell Measurement Bits</span>
                  <span className="mono">{currentPos?.bell_measurement_bits}</span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Expected Correction</span>
                  <span className="mono">{currentPos?.expected_correction}</span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Actual Correction</span>
                  <span
                    className={`mono ${
                      currentPos?.expected_correction !== currentPos?.actual_correction
                        ? styles.corrMismatch
                        : ''
                    }`}
                  >
                    {currentPos?.actual_correction}
                  </span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Measured Bit</span>
                  <span className={`mono ${!currentPos?.is_match ? styles.bitMismatch : ''}`}>
                    {currentPos?.final_measured_bit}
                  </span>
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>Teleportation Fidelity</span>
                  <FidelityBar value={currentPos?.fidelity} />
                </div>

                <div className={styles.metricRow}>
                  <span className={styles.metricLabel}>State Collapse</span>
                  <span className={`mono ${isCollapsed ? styles.textCollapsed : styles.textPreserved}`}>
                    {isCollapsed ? 'COLLAPSED (Z-Basis)' : 'PRESERVED'}
                  </span>
                </div>
              </>
            )}
          </div>

          {/* Quick Slider for Fast Scrubbing */}
          <div className={styles.sliderSection}>
            <div className={styles.sliderLabelRow}>
              <span className="mono text-muted">Scrub Position</span>
              <span className="mono">{selectedIndex} / {positions.length - 1}</span>
            </div>
            <input
              type="range"
              min="0"
              max={positions.length - 1}
              value={selectedIndex}
              onChange={(e) => setSelectedIndex(Number(e.target.value))}
              className={styles.slider}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
