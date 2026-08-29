import hashlib
from dataclasses import dataclass
from typing import Literal
import numpy as np


@dataclass
class SignatureElementMaterial:
    position_index: int
    basis: Literal["X", "Y", "Z"]
    bit_value: int


@dataclass
class KeyMaterial:
    message_digest: str
    signature_elements: list[SignatureElementMaterial]


def compute_message_digest(message: str) -> str:
    message_bytes = message.encode("utf-8")
    hasher = hashlib.sha256()
    hasher.update(message_bytes)
    return hasher.hexdigest()


def generate_signature_material(
    message: str,
    signature_length: int = 16,
    allowed_bases: list[str] = None,
    rng: np.random.Generator = None,
) -> KeyMaterial:
    if signature_length <= 0:
        raise ValueError(f"Signature length must be positive, got {signature_length}")

    if allowed_bases is None:
        allowed_bases = ["X", "Y", "Z"]

    for basis_candidate in allowed_bases:
        if basis_candidate.upper() not in ["X", "Y", "Z"]:
            raise ValueError(f"Invalid basis in allowed_bases: '{basis_candidate}'")

    cleaned_bases = [b.upper() for b in allowed_bases]

    if rng is None:
        rng = np.random.default_rng()

    message_digest = compute_message_digest(message)

    signature_elements = []
    for pos_index in range(signature_length):
        selected_basis = str(rng.choice(cleaned_bases))
        selected_bit = int(rng.integers(0, 2))
        element = SignatureElementMaterial(
            position_index=pos_index,
            basis=selected_basis,
            bit_value=selected_bit,
        )
        signature_elements.append(element)

    return KeyMaterial(
        message_digest=message_digest,
        signature_elements=signature_elements,
    )
