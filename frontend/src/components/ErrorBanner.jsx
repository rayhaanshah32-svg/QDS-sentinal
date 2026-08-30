import { AlertCircle, WifiOff } from 'lucide-react'
import styles from './ErrorBanner.module.css'

export default function ErrorBanner({ error }) {
  if (!error) return null

  const isNetwork = error.status === 0
  const is422 = error.status === 422

  return (
    <div className={`${styles.banner} ${is422 ? styles.validation : styles.error}`}>
      <div className={styles.icon}>
        {isNetwork
          ? <WifiOff size={15} strokeWidth={1.5} />
          : <AlertCircle size={15} strokeWidth={1.5} />
        }
      </div>
      <div className={styles.content}>
        <span className={styles.code}>
          {isNetwork ? 'NETWORK ERROR' : `HTTP ${error.status}`}
          {is422 ? ' — Validation / Threshold Ordering Violation' : ''}
        </span>
        <span className={styles.detail}>{error.detail}</span>
      </div>
    </div>
  )
}
