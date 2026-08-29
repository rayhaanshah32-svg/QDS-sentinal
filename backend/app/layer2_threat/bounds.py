"""
Layer 2 Threat Detection Engine – Finite-Sample Bounds and Threshold Validation

This module provides mathematically audited implementations of:
1. Hoeffding upper, lower, and tail bounds (clamped to [0.0, 1.0]).
2. Serfling upper, lower, and tail bounds for sampling without replacement
   from a finite population (including the finite-population correction term
   1 - (k-1)/n, and rejecting k > n).
3. Programmatic validation of the security threshold chain:
       e_upper < s_a < s_v < p_E
   which raises a ConfigurationWarning when violated.
"""

from __future__ import annotations

import math
import warnings


class ConfigurationWarning(UserWarning):
    """Warning raised when QDS threshold ordering chain e_upper < s_a < s_v < p_E is violated."""
    pass


# ---------------------------------------------------------------------------
# 1. Hoeffding Bounds
# ---------------------------------------------------------------------------

def hoeffding_upper_bound(p_obs: float, n: int, epsilon: float = 0.05) -> float:
    """
    Compute Hoeffding upper bound on the error rate for sample size n.

        e_upper = min(1.0, max(0.0, p_obs + sqrt(ln(1/epsilon) / (2n))))

    Parameters
    ----------
    p_obs : float
        Observed sample mismatch rate in [0.0, 1.0].
    n : int
        Sample size (number of evaluated positions).
    epsilon : float, optional
        Confidence parameter / failure probability (default 0.05 for 95% confidence).

    Returns
    -------
    float
        Upper-bounded error rate clamped strictly to [0.0, 1.0].
    """
    if n <= 0:
        return 1.0
    p_obs = max(0.0, min(1.0, p_obs))
    epsilon = max(1e-15, min(1.0, epsilon))
    margin = math.sqrt(math.log(1.0 / epsilon) / (2.0 * n))
    return max(0.0, min(1.0, p_obs + margin))


def hoeffding_lower_bound(p_obs: float, n: int, epsilon: float = 0.05) -> float:
    """
    Compute Hoeffding lower bound on the error rate for sample size n.

        e_lower = min(1.0, max(0.0, p_obs - sqrt(ln(1/epsilon) / (2n))))

    Returns
    -------
    float
        Lower-bounded error rate clamped strictly to [0.0, 1.0].
    """
    if n <= 0:
        return 0.0
    p_obs = max(0.0, min(1.0, p_obs))
    epsilon = max(1e-15, min(1.0, epsilon))
    margin = math.sqrt(math.log(1.0 / epsilon) / (2.0 * n))
    return max(0.0, min(1.0, p_obs - margin))


def hoeffding_tail_bound(observed_rate: float, e_honest: float, n: int) -> float:
    """
    Compute Hoeffding false-positive tail probability bound:
        P(rate >= observed_rate | true_rate = e_honest) <= exp(-2 * n * (observed_rate - e_honest)^2)

    Returns 1.0 (vacuous) if observed_rate <= e_honest or n <= 0.
    Clamped to [0.0, 1.0].
    """
    if n <= 0 or observed_rate <= e_honest:
        return 1.0
    gap = observed_rate - e_honest
    val = math.exp(-2.0 * n * (gap ** 2))
    return max(0.0, min(1.0, val))


# ---------------------------------------------------------------------------
# 2. Serfling Bounds (Finite-Population Sampling without Replacement)
# ---------------------------------------------------------------------------

def serfling_upper_bound(p_obs: float, k: int, n: int, epsilon: float = 0.05) -> float:
    """
    Compute Serfling upper bound for sample size k out of finite population size n.

    Serfling bound formula:
        margin = sqrt( (ln(1/epsilon) * (1 - (k-1)/n)) / (2k) )
        e_upper = min(1.0, max(0.0, p_obs + margin))

    Rejects k > n by raising ValueError.
    """
    if k > n:
        raise ValueError(f"Serfling bound error: sample size k={k} cannot exceed population size n={n}")
    if k <= 0 or n <= 0:
        return 1.0

    p_obs = max(0.0, min(1.0, p_obs))
    epsilon = max(1e-15, min(1.0, epsilon))

    # Finite-population correction term: (1 - (k-1)/n)
    fpc = 1.0 - (k - 1.0) / n
    fpc = max(0.0, fpc)

    margin = math.sqrt((math.log(1.0 / epsilon) * fpc) / (2.0 * k))
    return max(0.0, min(1.0, p_obs + margin))


def serfling_lower_bound(p_obs: float, k: int, n: int, epsilon: float = 0.05) -> float:
    """
    Compute Serfling lower bound for sample size k out of finite population size n.

    Rejects k > n by raising ValueError.
    """
    if k > n:
        raise ValueError(f"Serfling bound error: sample size k={k} cannot exceed population size n={n}")
    if k <= 0 or n <= 0:
        return 0.0

    p_obs = max(0.0, min(1.0, p_obs))
    epsilon = max(1e-15, min(1.0, epsilon))

    fpc = 1.0 - (k - 1.0) / n
    fpc = max(0.0, fpc)

    margin = math.sqrt((math.log(1.0 / epsilon) * fpc) / (2.0 * k))
    return max(0.0, min(1.0, p_obs - margin))


def serfling_tail_bound(observed_rate: float, e_honest: float, k: int, n: int) -> float:
    """
    Compute Serfling tail bound probability for sample size k out of population n:
        P <= exp( - (2 * k * (observed_rate - e_honest)^2) / (1 - (k-1)/n) )

    Rejects k > n by raising ValueError. Clamped to [0.0, 1.0].
    """
    if k > n:
        raise ValueError(f"Serfling bound error: sample size k={k} cannot exceed population size n={n}")
    if k <= 0 or n <= 0 or observed_rate <= e_honest:
        return 1.0

    gap = observed_rate - e_honest
    fpc = 1.0 - (k - 1.0) / n
    if fpc <= 0:
        return 0.0

    exponent = - (2.0 * k * (gap ** 2)) / fpc
    val = math.exp(exponent)
    return max(0.0, min(1.0, val))


# ---------------------------------------------------------------------------
# 3. Security Threshold Chain Validation (e_upper < s_a < s_v < p_E)
# ---------------------------------------------------------------------------

def validate_threshold_chain(
    e_upper: float,
    s_a: float,
    s_v: float,
    p_E: float,
) -> tuple[bool, str]:
    """
    Programmatically verify the non-negotiable QDS threshold chain:
        e_upper < s_a < s_v < p_E

    Raises ConfigurationWarning (via warnings.warn) if the chain is violated.

    Returns
    -------
    (is_valid, error_message)
    """
    violations = []
    if not (e_upper < s_a):
        violations.append(f"e_upper / e_honest ({e_upper:.4f}) >= s_a ({s_a:.4f})")
    if not (s_a < s_v):
        violations.append(f"s_a ({s_a:.4f}) >= s_v ({s_v:.4f})")
    if not (s_v < p_E):
        violations.append(f"s_v ({s_v:.4f}) >= p_E ({p_E:.4f})")

    if violations:
        msg = (
            f"Invalid QDS threshold ordering chain e_upper < s_a < s_v < p_E. "
            f"Violations: {'; '.join(violations)}. "
            f"Configured values: e_upper={e_upper:.4f}, s_a={s_a:.4f}, s_v={s_v:.4f}, p_E={p_E:.4f}."
        )
        warnings.warn(msg, ConfigurationWarning, stacklevel=2)
        return False, msg

    return True, ""
