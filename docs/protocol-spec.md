# QDS Sentinel - Layer 1 Protocol Specification

## 1. Overview

This document specifies the mathematical conventions, quantum gate definitions, state representations, teleportation circuit mechanics, and Pauli correction mappings implemented in **Layer 1: Protocol Simulation Engine** of QDS Sentinel.

---

## 2. Qubit Ordering Convention

QDS Sentinel uses standard big-endian computational basis indexing.

For an $n$-qubit state:
$$|q_0 q_1 \dots q_{n-1}\rangle$$

- **Qubit 0 ($q_0$)** is the most significant qubit (leftmost).
- **Qubit $n-1$ ($q_{n-1}$)** is the least significant qubit (rightmost).
- The basis state $|b_0 b_1 \dots b_{n-1}\rangle$ corresponds to integer index:
  $$i = \sum_{k=0}^{n-1} b_k 2^{n-1-k}$$

For the 3-qubit teleportation circuit:
- $q_0$: Sender's input qubit carrying state $|\psi\rangle$
- $q_1$: Sender's half of the entangled Bell pair
- $q_2$: Receiver's half of the entangled Bell pair

---

## 3. Quantum States

### 3.1 Computational Basis
- $|0\rangle = \begin{pmatrix} 1 \\ 0 \end{pmatrix}$
- $|1\rangle = \begin{pmatrix} 0 \\ 1 \end{pmatrix}$

### 3.2 Pauli Eigenstates
All states are normalized complex column vectors ($\|\psi\| = 1$):

| Basis | Bit | Ket | Vector |
|---|---|---|---|
| **Z** | `0` | $\|0\rangle$ | $[1.0, 0.0]^T$ |
| **Z** | `1` | $\|1\rangle$ | $[0.0, 1.0]^T$ |
| **X** | `0` | $\|+\rangle$ | $[\frac{1}{\sqrt{2}}, \frac{1}{\sqrt{2}}]^T$ |
| **X** | `1` | $\|-\rangle$ | $[\frac{1}{\sqrt{2}}, -\frac{1}{\sqrt{2}}]^T$ |
| **Y** | `0` | $\|+i\rangle$ | $[\frac{1}{\sqrt{2}}, \frac{i}{\sqrt{2}}]^T$ |
| **Y** | `1` | $\|-i\rangle$ | $[\frac{1}{\sqrt{2}}, -\frac{i}{\sqrt{2}}]^T$ |

---

## 4. Bell States

Two-qubit maximally entangled states on qubits $(q_1, q_2)$:

- **$\Phi^+$ (`PHI_PLUS`)**: $\frac{1}{\sqrt{2}}(|00\rangle + |11\rangle) = [\frac{1}{\sqrt{2}}, 0, 0, \frac{1}{\sqrt{2}}]^T$
- **$\Phi^-$ (`PHI_MINUS`)**: $\frac{1}{\sqrt{2}}(|00\rangle - |11\rangle) = [\frac{1}{\sqrt{2}}, 0, 0, -\frac{1}{\sqrt{2}}]^T$
- **$\Psi^+$ (`PSI_PLUS`)**: $\frac{1}{\sqrt{2}}(|01\rangle + |10\rangle) = [0, \frac{1}{\sqrt{2}}, \frac{1}{\sqrt{2}}, 0]^T$
- **$\Psi^-$ (`PSI_MINUS`)**: $\frac{1}{\sqrt{2}}(|01\rangle - |10\rangle) = [0, \frac{1}{\sqrt{2}}, -\frac{1}{\sqrt{2}}, 0]^T$

---

## 5. Quantum Gates

### 5.1 Single Qubit Unitaries
- **Identity ($I$)**: $\begin{pmatrix} 1 & 0 \\ 0 & 1 \end{pmatrix}$
- **Pauli-X ($X$)**: $\begin{pmatrix} 0 & 1 \\ 1 & 0 \end{pmatrix}$
- **Pauli-Y ($Y$)**: $\begin{pmatrix} 0 & -i \\ i & 0 \end{pmatrix}$
- **Pauli-Z ($Z$)**: $\begin{pmatrix} 1 & 0 \\ 0 & -1 \end{pmatrix}$
- **Hadamard ($H$)**: $\frac{1}{\sqrt{2}}\begin{pmatrix} 1 & 1 \\ 1 & -1 \end{pmatrix}$

### 5.2 Two-Qubit Controlled-NOT ($CNOT$)
$$\text{CNOT} = |0\rangle\langle 0| \otimes I + |1\rangle\langle 1| \otimes X = \begin{pmatrix} 1 & 0 & 0 & 0 \\ 0 & 1 & 0 & 0 \\ 0 & 0 & 0 & 1 \\ 0 & 0 & 1 & 0 \end{pmatrix}$$

---

## 6. Teleportation Protocol Steps

1. **State Preparation**: Sender has input qubit $q_0$ in state $|\psi\rangle = \alpha|0\rangle + \beta|1\rangle$.
2. **Entanglement Sharing**: Bell pair $|\Phi^+\rangle_{12}$ is generated between sender $q_1$ and receiver $q_2$.
3. **Composite State**:
   $$|\Psi_{012}\rangle = |\psi\rangle_0 \otimes |\Phi^+\rangle_{12} = \frac{1}{\sqrt{2}}\big(\alpha|000\rangle + \alpha|011\rangle + \beta|100\rangle + \beta|111\rangle\big)$$
4. **CNOT Operation**: Apply $\text{CNOT}_{0 \to 1}$:
   $$|\Psi_{012}'\rangle = \frac{1}{\sqrt{2}}\big(\alpha|000\rangle + \alpha|011\rangle + \beta|110\rangle + \beta|101\rangle\big)$$
5. **Hadamard Operation**: Apply $H_0$:
   $$|\Psi_{012}''\rangle = \frac{1}{2}\Big[|00\rangle(\alpha|0\rangle + \beta|1\rangle) + |01\rangle(\alpha|1\rangle + \beta|0\rangle) + |10\rangle(\alpha|0\rangle - \beta|1\rangle) + |11\rangle(\alpha|1\rangle - \beta|0\rangle)\Big]$$
6. **Bell Measurement**: Sender measures $(q_0, q_1)$ in the computational basis.
7. **Classical Feedforward & Pauli Correction**:
   Based on measurement outcome bits $b_0 b_1$:

| Measurement Bits ($b_0 b_1$) | Receiver State Before Correction | Required Pauli Correction | State After Correction |
|---|---|---|---|
| `00` | $\alpha\|0\rangle + \beta\|1\rangle = \|\psi\rangle$ | **$I$** | $\|\psi\rangle$ |
| `01` | $\alpha\|1\rangle + \beta\|0\rangle = X\|\psi\rangle$ | **$X$** | $\|\psi\rangle$ |
| `10` | $\alpha\|0\rangle - \beta\|1\rangle = Z\|\psi\rangle$ | **$Z$** | $\|\psi\rangle$ |
| `11` | $\alpha\|1\rangle - \beta\|0\rangle = XZ\|\psi\rangle$ | **$XZ$** ($Z$ after $X$) | $\|\psi\rangle$ |

---

## 7. State Fidelity

The state fidelity between the original input state $|\psi\rangle$ and corrected receiver state $|\phi\rangle$ is defined as:
$$F(|\psi\rangle, |\phi\rangle) = |\langle\psi|\phi\rangle|^2$$

Under ideal noiseless conditions, $F(|\psi\rangle, |\phi\rangle) \ge 0.999999$ across all six Pauli eigenstates and all four Bell measurement branches.

---

## 8. Teleportation-Mediated QDS Simulation Signature Block

1. Message $M$ is hashed using SHA-256 to produce $H(M)$.
2. For each position $i \in \{0, \dots, L-1\}$ in the signature:
   - A basis $B_i \in \{X, Y, Z\}$ and bit value $b_i \in \{0, 1\}$ are selected using a seeded PRNG.
   - Sender prepares Pauli eigenstate $|\psi(B_i, b_i)\rangle$.
   - State is teleported to the recipient via the 3-qubit teleportation channel.
   - Recipient measures the received state in basis $B_i$ to observe bit $b_i'$.
3. The verification primitive compares $b_i$ and $b_i'$, calculating mismatch count, mismatch rate, and average channel fidelity.
