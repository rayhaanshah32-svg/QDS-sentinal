import styles from './SimDisclaimer.module.css'

export default function SimDisclaimer({ text }) {
  if (!text) return null
  return (
    <div className={styles.disclaimer}>
      <span className={styles.label}>Simulation disclaimer</span>
      {text}
    </div>
  )
}
