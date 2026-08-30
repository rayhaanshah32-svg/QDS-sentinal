import styles from './DecisionBanner.module.css'

export default function DecisionBanner({ securityDecision, threatLevel }) {
  const isAccept = securityDecision && securityDecision.startsWith('ACCEPT')
  const colorClass = isAccept ? styles.accept : styles.reject

  return (
    <div className={`${styles.banner} ${colorClass}`}>
      <span className={styles.verdict}>{isAccept ? 'ACCEPT' : 'REJECT'}</span>
      <span className={styles.detail}>{securityDecision}</span>
    </div>
  )
}
