from dataclasses import dataclass


@dataclass
class Layer2Config:
    s_a: float = 0.10
    s_v: float = 0.20
    p_E: float = 0.25
    q_alert: float = 0.11
    c_tamper_rate: float = 0.0
    f_floor: float = 0.999
    e_honest: float = 0.0
    forwarding_split: float = 0.5
    max_replay_window: int = 1000
    verification_mode: str = "direct"
    min_basis_samples: int = 1


default_config = Layer2Config()
