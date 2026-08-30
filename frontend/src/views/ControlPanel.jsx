import { useState } from 'react'
import { ChevronDown, ChevronRight, Play, Zap } from 'lucide-react'
import { runAssess, runAttackSimulate, runLayer1Simulate, getExampleClean, getExampleReplay, getExampleForgery } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'
import styles from './ControlPanel.module.css'

const BELL_STATES = ['PHI_PLUS', 'PHI_MINUS', 'PSI_PLUS', 'PSI_MINUS']
const ALL_BASES = ['X', 'Y', 'Z']
const VERIFICATION_MODES = ['direct', 'forwarded']
const ATTACK_TYPES = [
  { value: '', label: 'None (clean assessment)' },
  { value: 'REPLAY', label: 'REPLAY' },
  { value: 'FULL_FORGERY', label: 'FULL_FORGERY' },
  { value: 'PARTIAL_FORGERY', label: 'PARTIAL_FORGERY' },
  { value: 'CORRECTION_TAMPERING', label: 'CORRECTION_TAMPERING' },
  { value: 'INTERCEPT_RESEND', label: 'INTERCEPT_RESEND' },
  { value: 'CHANNEL_MANIPULATION', label: 'CHANNEL_MANIPULATION' },
  { value: 'FIDELITY_DEGRADATION', label: 'FIDELITY_DEGRADATION' },
  { value: 'BOB_REPUDIATION', label: 'BOB_REPUDIATION' },
]

function buildSimulationRequest(form) {
  return {
    message: form.message,
    sender_id: form.sender_id,
    recipient_id: form.recipient_id,
    signature_length: parseInt(form.signature_length, 10),
    seed: form.seed !== '' ? parseInt(form.seed, 10) : null,
    bell_state: form.bell_state,
    bases_allowed: form.bases_allowed,
    session_id: form.session_id || null,
    nonce: form.nonce || null,
    sequence_number: parseInt(form.sequence_number, 10),
  }
}

function syncAttackedSession(session, assessment, attackType, intensity, targetBasis) {
  if (!session || !session.signature_positions) return session
  const copy = JSON.parse(JSON.stringify(session))
  const positions = copy.signature_positions

  if (attackType === 'CORRECTION_TAMPERING' && assessment?.correction_consistency?.inconsistent_positions) {
    const inconsistentSet = new Set(assessment.correction_consistency.inconsistent_positions)
    for (const p of positions) {
      if (inconsistentSet.has(p.index)) {
        let tampered = 'I'
        if (p.expected_correction === 'I') tampered = 'X'
        else if (p.expected_correction === 'X') tampered = 'I'
        else if (p.expected_correction === 'Z') tampered = 'X'
        p.actual_correction = tampered
        p.fidelity = 0.5
        p.final_measured_bit = 1 - p.expected_bit
        p.is_match = false
      }
    }
  } else if (attackType === 'FIDELITY_DEGRADATION' && assessment?.fidelity_analysis) {
    const minFid = assessment.fidelity_analysis.min_fidelity || 0.70
    for (const p of positions) {
      p.fidelity = minFid
    }
  } else if (attackType === 'PARTIAL_FORGERY' || attackType === 'INTERCEPT_RESEND' || attackType === 'CHANNEL_MANIPULATION' || attackType === 'BOB_REPUDIATION') {
    const mismatchCount = Math.round(positions.length * (assessment?.qber_analysis?.global_mismatch_rate || 0))
    for (let i = 0; i < Math.min(mismatchCount, positions.length); i++) {
      positions[i].final_measured_bit = 1 - positions[i].expected_bit
      positions[i].is_match = false
    }
  }

  return copy
}

export default function ControlPanel({ onResult }) {
  const [form, setForm] = useState({
    message: 'PAYLOAD_TRANSFER_AUTHENTIC_001',
    sender_id: 'alice',
    recipient_id: 'bob',
    signature_length: '16',
    seed: '42',
    bell_state: 'PHI_PLUS',
    bases_allowed: ['X', 'Y', 'Z'],
    session_id: '',
    nonce: '',
    sequence_number: '1',
    verification_mode: 'direct',
    s_a: '0.10',
    s_v: '0.20',
    e_honest: '0.00',
    expected_sender_id: '',
    expected_recipient_id: '',
    requested_verifier_id: '',
    attack_type: '',
    intensity: '0.25',
    target_basis: '',
  })

  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  function setField(name, value) {
    setForm(prev => ({ ...prev, [name]: value }))
  }

  function toggleBasis(basis) {
    setForm(prev => {
      const current = prev.bases_allowed
      if (current.includes(basis)) {
        if (current.length === 1) return prev
        return { ...prev, bases_allowed: current.filter(b => b !== basis) }
      }
      return { ...prev, bases_allowed: [...current, basis] }
    })
  }

  async function handleRun() {
    setLoading(true)
    setError(null)

    const simulation = buildSimulationRequest(form)
    const advancedOverrides = {
      verification_mode: form.verification_mode,
      s_a: parseFloat(form.s_a),
      s_v: parseFloat(form.s_v),
      e_honest: parseFloat(form.e_honest),
      expected_sender_id: form.expected_sender_id || null,
      expected_recipient_id: form.expected_recipient_id || null,
      requested_verifier_id: form.requested_verifier_id || null,
    }

    const [sessionResult, assessmentResult] = await Promise.all([
      runLayer1Simulate(simulation),
      form.attack_type
        ? runAttackSimulate({
            simulation,
            ...advancedOverrides,
            attack_type: form.attack_type,
            intensity: parseFloat(form.intensity),
            target_basis: form.target_basis || null,
          })
        : runAssess({ simulation, ...advancedOverrides }),
    ])

    setLoading(false)

    if (assessmentResult.error) {
      setError(assessmentResult.error)
      return
    }

    const assessment = form.attack_type
      ? assessmentResult.data.assessment
      : assessmentResult.data

    const attackMeta = form.attack_type ? assessmentResult.data.attack_metadata : null

    let finalSession = sessionResult.error ? null : sessionResult.data
    if (finalSession && form.attack_type) {
      finalSession = syncAttackedSession(finalSession, assessment, form.attack_type, parseFloat(form.intensity), form.target_basis)
    }

    onResult({
      assessment,
      sessionResult: finalSession,
      attackMeta,
    })
  }

  async function handleExample(fetchFn, label, simParams) {
    setLoading(true)
    setError(null)
    const [result, sessionRes] = await Promise.all([
      fetchFn(),
      runLayer1Simulate(simParams),
    ])
    setLoading(false)
    if (result.error) {
      setError(result.error)
      return
    }
    onResult({
      assessment: result.data,
      sessionResult: sessionRes.error ? null : sessionRes.data,
      attackMeta: null,
    })
  }

  const hasAttack = Boolean(form.attack_type)

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <h2>Simulation Control Panel</h2>
        <div className={styles.quickExamples}>
          <span className={styles.quickLabel}>Quick examples:</span>
          <button
            onClick={() => handleExample(getExampleClean, 'clean', {
              message: 'AUTHENTICATED_TRANSACTION_PAYLOAD_CLEAN',
              sender_id: 'alice',
              recipient_id: 'bob',
              signature_length: 16,
              seed: 42,
              bell_state: 'PHI_PLUS',
              bases_allowed: ['X', 'Y', 'Z'],
              sequence_number: 1,
            })}
            disabled={loading}
          >
            Clean session
          </button>
          <button
            onClick={() => handleExample(getExampleReplay, 'replay', {
              message: 'AUTHENTICATED_TRANSACTION_REPLAY_TEST',
              sender_id: 'alice',
              recipient_id: 'bob',
              signature_length: 16,
              seed: 99,
              bell_state: 'PHI_PLUS',
              bases_allowed: ['X', 'Y', 'Z'],
              sequence_number: 1,
            })}
            disabled={loading}
          >
            Replay attack
          </button>
          <button
            onClick={() => handleExample(getExampleForgery, 'forgery', {
              message: 'AUTHENTIC_MESSAGE',
              sender_id: 'alice',
              recipient_id: 'bob',
              signature_length: 16,
              seed: 77,
              bell_state: 'PHI_PLUS',
              bases_allowed: ['X', 'Y', 'Z'],
              sequence_number: 1,
            })}
            disabled={loading}
          >
            Digest forgery
          </button>
        </div>
      </div>

      <ErrorBanner error={error} />

      <div className={styles.grid}>
        <div className={styles.formGroup}>
          <label htmlFor="cp-message">Message</label>
          <input
            id="cp-message"
            value={form.message}
            onChange={e => setField('message', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-sender">Sender ID</label>
          <input
            id="cp-sender"
            value={form.sender_id}
            onChange={e => setField('sender_id', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-recipient">Recipient ID</label>
          <input
            id="cp-recipient"
            value={form.recipient_id}
            onChange={e => setField('recipient_id', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-siglen">Signature Length</label>
          <input
            id="cp-siglen"
            type="number"
            min="1"
            max="4096"
            value={form.signature_length}
            onChange={e => setField('signature_length', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-seed">Seed (optional)</label>
          <input
            id="cp-seed"
            type="number"
            value={form.seed}
            onChange={e => setField('seed', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-seqnum">Sequence Number</label>
          <input
            id="cp-seqnum"
            type="number"
            min="1"
            value={form.sequence_number}
            onChange={e => setField('sequence_number', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-bell">Bell State</label>
          <select
            id="cp-bell"
            value={form.bell_state}
            onChange={e => setField('bell_state', e.target.value)}
          >
            {BELL_STATES.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        <div className={styles.formGroup}>
          <label>Bases Allowed</label>
          <div className={styles.checkboxGroup}>
            {ALL_BASES.map(basis => (
              <label key={basis} className={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  id={`cp-basis-${basis}`}
                  checked={form.bases_allowed.includes(basis)}
                  onChange={() => toggleBasis(basis)}
                />
                {basis}
              </label>
            ))}
          </div>
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-vmode">Verification Mode</label>
          <select
            id="cp-vmode"
            value={form.verification_mode}
            onChange={e => setField('verification_mode', e.target.value)}
          >
            {VERIFICATION_MODES.map(m => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-session">Session ID (optional)</label>
          <input
            id="cp-session"
            value={form.session_id}
            onChange={e => setField('session_id', e.target.value)}
          />
        </div>

        <div className={styles.formGroup}>
          <label htmlFor="cp-nonce">Nonce (optional)</label>
          <input
            id="cp-nonce"
            value={form.nonce}
            onChange={e => setField('nonce', e.target.value)}
          />
        </div>
      </div>

      <div className={styles.attackSection}>
        <div className={styles.formGroup}>
          <label htmlFor="cp-attack">Attack Type</label>
          <select
            id="cp-attack"
            value={form.attack_type}
            onChange={e => setField('attack_type', e.target.value)}
          >
            {ATTACK_TYPES.map(a => (
              <option key={a.value} value={a.value}>{a.label}</option>
            ))}
          </select>
        </div>

        {hasAttack && (
          <div className={styles.attackParams}>
            <div className={styles.formGroup}>
              <label htmlFor="cp-intensity">
                Intensity (q): <span className="mono">{parseFloat(form.intensity).toFixed(2)}</span>
              </label>
              <input
                id="cp-intensity"
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={form.intensity}
                onChange={e => setField('intensity', e.target.value)}
                className={styles.slider}
              />
            </div>
            <div className={styles.formGroup}>
              <label htmlFor="cp-targetbasis">Target Basis (for CHANNEL_MANIPULATION)</label>
              <select
                id="cp-targetbasis"
                value={form.target_basis}
                onChange={e => setField('target_basis', e.target.value)}
              >
                <option value="">— none —</option>
                {ALL_BASES.map(b => <option key={b} value={b}>{b}</option>)}
              </select>
            </div>
          </div>
        )}
      </div>

      <div className={styles.advancedToggle}>
        <button
          className={styles.toggleBtn}
          onClick={() => setAdvancedOpen(o => !o)}
          id="cp-advanced-toggle"
        >
          {advancedOpen
            ? <ChevronDown size={14} strokeWidth={1.5} />
            : <ChevronRight size={14} strokeWidth={1.5} />
          }
          Advanced thresholds &amp; identity overrides
        </button>
      </div>

      {advancedOpen && (
        <div className={styles.advancedGrid}>
          <div className={styles.formGroup}>
            <label htmlFor="cp-sa">s_a (accept threshold)</label>
            <input
              id="cp-sa"
              type="number"
              step="0.01"
              min="0"
              max="1"
              value={form.s_a}
              onChange={e => setField('s_a', e.target.value)}
            />
          </div>
          <div className={styles.formGroup}>
            <label htmlFor="cp-sv">s_v (verify threshold)</label>
            <input
              id="cp-sv"
              type="number"
              step="0.01"
              min="0"
              max="1"
              value={form.s_v}
              onChange={e => setField('s_v', e.target.value)}
            />
          </div>
          <div className={styles.formGroup}>
            <label htmlFor="cp-ehonest">e_honest (background error)</label>
            <input
              id="cp-ehonest"
              type="number"
              step="0.01"
              min="0"
              max="0.99"
              value={form.e_honest}
              onChange={e => setField('e_honest', e.target.value)}
            />
          </div>
          <div className={styles.formGroup}>
            <label htmlFor="cp-expsender">Expected Sender ID</label>
            <input
              id="cp-expsender"
              value={form.expected_sender_id}
              onChange={e => setField('expected_sender_id', e.target.value)}
            />
          </div>
          <div className={styles.formGroup}>
            <label htmlFor="cp-exprecipient">Expected Recipient ID</label>
            <input
              id="cp-exprecipient"
              value={form.expected_recipient_id}
              onChange={e => setField('expected_recipient_id', e.target.value)}
            />
          </div>
          <div className={styles.formGroup}>
            <label htmlFor="cp-verifier">Requesting Verifier ID</label>
            <input
              id="cp-verifier"
              value={form.requested_verifier_id}
              onChange={e => setField('requested_verifier_id', e.target.value)}
            />
          </div>
        </div>
      )}

      <div className={styles.actions}>
        <button
          id="cp-run-btn"
          className="primary"
          onClick={handleRun}
          disabled={loading}
        >
          {loading
            ? <span className="pulse">Running…</span>
            : (
              <span className={styles.runLabel}>
                {hasAttack ? <Zap size={14} strokeWidth={1.5} /> : <Play size={14} strokeWidth={1.5} />}
                {hasAttack ? 'Run Attack Simulation' : 'Run Assessment'}
              </span>
            )
          }
        </button>
        <span className={styles.hint}>
          {hasAttack
            ? 'Calls POST /attack-simulate + POST /layer1/simulate'
            : 'Calls POST /assess + POST /layer1/simulate'
          }
        </span>
      </div>
    </div>
  )
}
