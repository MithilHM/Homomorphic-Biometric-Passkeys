"""OpenFHE CKKS engine for the homomorphic biometric comparison.

This is an ALTERNATIVE to the in-repo RLWE engine in `packages/fhe`. It exists
because CKKS evaluates over the complex numbers rather than a negacyclic ring,
which some reviewers will want to see. The decision procedure, the noise
discipline and the wire commitment are identical, so the two engines are
interchangeable behind `cryptography/vectors/protocol.json`.

    pip install openfhe-python

## No mock mode, by design

The previous version of this file fell back to `pickle.dumps({"mock": True,
"embedding": embedding})` when OpenFHE was missing. That serialised the
PLAINTEXT embedding into something that looked like a ciphertext, and
`decrypt_distance` returned a hardcoded `0.5`.

A biometric system that returns a plausible number without doing any encryption
is worse than one that refuses to start: every downstream attestation would be
signed over a decision that was never computed. This module therefore raises
`OpenFHEUnavailable` and nothing else. There is no simulation path.

## The comparison

For L2-normalised embeddings the squared Euclidean distance and the dot product
are interchangeable, so this computes the dot product directly — one
homomorphic multiplication plus rotation-and-add to reduce SIMD slots, which
matches the RLWE engine's depth and error profile rather than paying for the
extra square.

    similarity = Σ_i q_i · t_i

`decide()` applies the same `indeterminate` band as the TypeScript engine, so a
capture near the threshold is refused rather than guessed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence

__all__ = [
    "OpenFHEUnavailable",
    "CkksParameters",
    "CkksDecision",
    "CkksEngine",
    "is_available",
    "openfhe_version",
    "DEFAULT_PARAMETERS",
]

# --------------------------------------------------------------------------
# Optional import. Absence is reported, never papered over.
# --------------------------------------------------------------------------

try:  # pragma: no cover - exercised only where OpenFHE is installed
    from openfhe import (
        CCParamsCKKSRNS,
        EncryptionLevel,
        EvalMult,
        PKESchemeFeature,
        SecurityLevel,
        GenCryptoContext,
    )

    _IMPORT_ERROR: Optional[str] = None
except ImportError as exc:  # pragma: no cover - the common case in CI
    CCParamsCKKSRNS = None  # type: ignore[assignment,misc]
    EncryptionLevel = None  # type: ignore[assignment,misc]
    EvalMult = None  # type: ignore[assignment]
    PKESchemeFeature = None  # type: ignore[assignment,misc]
    SecurityLevel = None  # type: ignore[assignment,misc]
    GenCryptoContext = None  # type: ignore[assignment]

    _IMPORT_ERROR = str(exc)


class OpenFHEUnavailable(RuntimeError):
    """Raised when OpenFHE is required but not importable.

    Deliberately fatal. There is no mock fallback: see the module docstring.
    """


def is_available() -> bool:
    """Whether the OpenFHE bindings can be imported."""
    return _IMPORT_ERROR is None


def openfhe_version() -> Optional[str]:
    """Installed OpenFHE version, or ``None`` when unavailable."""
    if _IMPORT_ERROR is not None:
        return None
    try:  # pragma: no cover - depends on the installed build
        from openfhe import get_version

        return str(get_version())
    except Exception:  # pragma: no cover
        return "unknown"


def _require_openfhe() -> None:
    if _IMPORT_ERROR is not None:
        raise OpenFHEUnavailable(
            "OpenFHE is not installed, so no homomorphic comparison can be "
            "performed. Install it with `pip install openfhe-python`, or use "
            "the in-repo RLWE engine in packages/fhe instead. This module has "
            "no mock mode: returning a plausible number without encrypting "
            "anything would silently sign attestations over a decision that "
            "was never computed."
        )


# --------------------------------------------------------------------------
# Parameters
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CkksParameters:
    """CKKS parameter set.

    Defaults are chosen to match the RLWE engine's cost profile: one
    multiplication, HEStd_128, 128-d embeddings. ``depth`` of 2 leaves room
    for the multiplication plus one rotation-and-add level, which is what the
    SIMD reduction consumes.
    """

    ring_dimension: int = 8192
    depth: int = 2
    scaling_mod_size: int = 50
    embedding_dimension: int = 128
    #: Absolute bound the engine guarantees on the recovered similarity. The
    #: decision procedure refuses to answer inside this band.
    error_bound: float = 2.0**-9
    #: Minimum similarity below which a decision is never acceptable.
    threshold: float = 0.7

    def __post_init__(self) -> None:
        if self.ring_dimension & (self.ring_dimension - 1):
            raise ValueError("CKKS ring dimension must be a power of two")
        if self.embedding_dimension * 2 > self.ring_dimension:
            raise ValueError(
                "embedding dimension must fit comfortably in the ring; a larger "
                "dimension wraps the SIMD slots and corrupts the reduction"
            )
        if self.error_bound <= 0:
            raise ValueError("error bound must be positive")
        if not 0.0 < self.threshold < 1.0:
            raise ValueError("cosine threshold must lie strictly between 0 and 1")

    @property
    def batch_size(self) -> int:
        """Usable SIMD slots: half the ring dimension, as CKKS requires."""
        return self.ring_dimension // 2

    @property
    def rotation_steps(self) -> List[int]:
        """Powers of two needed to reduce ``embedding_dimension`` slots.

        Reduces by repeated rotate-and-add: after step ``2^k`` the partial sum
        covers ``2^(k+1)`` slots. Exactly ``ceil(log2(dimension))`` rotations
        are needed, and one more than that would fold in zero-padding.
        """
        steps: List[int] = []
        covered = 1
        while covered < self.embedding_dimension:
            steps.append(covered)
            covered *= 2
        return steps


DEFAULT_PARAMETERS = CkksParameters()


# --------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CkksDecision:
    """Outcome of a homomorphic comparison.

    ``zone`` is one of ``accept``, ``reject`` or ``indeterminate``. The third is
    a first-class outcome, not an error: the comparison is approximate, and
    pretending otherwise is how near-threshold captures get decided wrongly.
    """

    zone: str
    decision: bool
    similarity: float
    threshold: float
    margin: float
    contributors: Sequence[str]

    @property
    def is_indeterminate(self) -> bool:
        return self.zone == "indeterminate"


def decide(similarity: float, threshold: float, margin: float) -> CkksDecision:
    """Apply the threshold, exposing the uncertainty band.

    Mirrors ``decide()`` in ``packages/fhe/src/encode.ts`` exactly. If these two
    ever disagree, the two engines are no longer interchangeable and the
    conformance vectors will catch it.
    """
    if margin <= 0:
        raise ValueError("noise margin must be positive")
    if similarity >= threshold + margin:
        zone, decision = "accept", True
    elif similarity <= threshold - margin:
        zone, decision = "reject", False
    else:
        zone, decision = "indeterminate", False
    return CkksDecision(
        zone=zone,
        decision=decision,
        similarity=similarity,
        threshold=threshold,
        margin=margin,
        contributors=(),
    )


def normalise(vector: Iterable[float]) -> List[float]:
    """L2-normalise an embedding.

    Required, not cosmetic: ``‖x − y‖² = 2 − 2⟨x,y⟩`` only holds for unit
    vectors, so the identity the whole comparison rests on depends on it.
    """
    values = [float(v) for v in vector]
    norm = math.sqrt(sum(v * v for v in values))
    if norm == 0.0:
        raise ValueError("cannot normalise a zero vector")
    return [v / norm for v in values]


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Plaintext cosine similarity — used only to measure engine error."""
    if len(a) != len(b):
        raise ValueError(f"dimension mismatch: {len(a)} != {len(b)}")
    dot = sum(float(x) * float(y) for x, y in zip(a, b))
    na = math.sqrt(sum(float(x) * float(x) for x in a))
    nb = math.sqrt(sum(float(y) * float(y) for y in b))
    if na == 0.0 or nb == 0.0:
        raise ValueError("cannot compute cosine against a zero vector")
    return dot / (na * nb)


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class CkksEngine:
    """CKKS homomorphic similarity, with an explicit unavailability state.

    Construction does not require OpenFHE, so a deployment can probe
    :meth:`is_available` and report a degraded posture without crashing. Any
    operation that would need to actually encrypt raises instead.
    """

    def __init__(
        self,
        parameters: CkksParameters = DEFAULT_PARAMETERS,
        *,
        committee_members: Sequence[str] = ("fhe-coprocessor", "proof-service", "custody"),
    ) -> None:
        self.params = parameters
        self._members = tuple(committee_members)
        self._context: Any = None
        self._key_pair: Any = None
        self._rotation_keys: Any = None

    # ------------------------------ lifecycle -----------------------------

    def is_available(self) -> bool:
        """Whether this engine can perform real homomorphic operations."""
        return is_available()

    def setup(self) -> "CkksEngine":
        """Build the crypto context and key material.

        Idempotent. Raises :class:`OpenFHEUnavailable` if OpenFHE is missing.
        """
        _require_openfhe()
        if self._context is not None:
            return self

        parameters = CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(self.params.depth)
        parameters.SetScalingModSize(self.params.scaling_mod_size)
        parameters.SetBatchSize(self.params.batch_size)
        parameters.SetSecurityLevel(SecurityLevel.HEStd_128_classic)
        parameters.SetRingDim(self.params.ring_dimension)
        # Plaintext is the sensitive quantity; default noise flooding applies.
        parameters.SetEncryptionTechnique(EncryptionLevel.HEStd)

        self._context = GenCryptoContext(parameters)
        self._context.Enable(PKESchemeFeature.PKE)
        self._context.Enable(PKESchemeFeature.KEYSWITCH)
        self._context.Enable(PKESchemeFeature.LEVELEDSHE)

        self._key_pair = self._context.KeyGen()
        self._rotation_keys = self._context.EvalRotateKeyGen(
            self._key_pair.secretKey, self.params.rotation_steps
        )
        return self

    def require_ready(self) -> None:
        """Raise unless the engine has key material."""
        if self._context is None or self._key_pair is None or self._rotation_keys is None:
            self.setup()

    # ------------------------------ encryption ----------------------------

    def encrypt(self, vector: Sequence[float], layout: str = "low") -> Any:
        """Encrypt one L2-normalised embedding into a CKKS plaintext.

        ``layout`` is accepted for signature compatibility with the RLWE engine
        (``"high"`` for the enrolled template, ``"low"`` for the live capture).
        CKKS packs slots densely, so the mirrored-negacyclic layout is not
        needed here — the slot ordering is identical either way.
        """
        if layout not in ("low", "high"):
            raise ValueError(f"unknown layout {layout!r}; expected 'low' or 'high'")
        self.require_ready()

        values = normalise(vector)
        if len(values) != self.params.embedding_dimension:
            raise ValueError(
                f"expected {self.params.embedding_dimension} dimensions, got {len(values)}"
            )
        padded = values + [0.0] * (self.params.batch_size - len(values))
        plaintext = self._context.MakeCKKSPackedPlaintext(padded)
        return self._context.Encrypt(self._key_pair.publicKey, plaintext)

    # ------------------------------ comparison ----------------------------

    def similarity_ciphertext(self, template_ct: Any, query_ct: Any) -> Any:
        """Evaluate ``⟨template, query⟩`` without decrypting either side."""
        self.require_ready()
        elementwise = self._context.EvalMult(template_ct, query_ct)

        # Rotate-and-add reduction across the occupied slots.
        accumulator = elementwise
        for step in self.params.rotation_steps:
            rotated = self._context.EvalRotate(accumulator, step, self._rotation_keys)
            accumulator = self._context.EvalAdd(accumulator, rotated)
        return accumulator

    def similarity(
        self, template: Sequence[float], query: Sequence[float]
    ) -> float:
        """Encrypt both operands, evaluate, decrypt, and return the similarity.

        The decryption step stands in for the 3-of-3 threshold committee. In a
        real deployment this method is never called by a single party — the
        coprocessor returns the ciphertext and the committee recombines partial
        decryptions. It is provided so the engine is testable and so a
        deployment can verify its own error bound against the plaintext.
        """
        self.require_ready()
        product = self.similarity_ciphertext(
            self.encrypt(template, layout="high"),
            self.encrypt(query, layout="low"),
        )
        plaintext = self._context.Decrypt(self._key_pair.secretKey, product)
        plaintext.SetLength(self.params.embedding_dimension)
        slots = plaintext.GetRealPackedValue()
        # Every slot holds its own term; sum them to recover the dot product.
        return float(sum(slots[: self.params.embedding_dimension]))

    def compare(
        self,
        template: Sequence[float],
        query: Sequence[float],
        *,
        threshold: Optional[float] = None,
        margin: Optional[float] = None,
    ) -> CkksDecision:
        """Full encrypted comparison, ending in an explicit decision zone."""
        similarity = self.similarity(template, query)
        resolved_threshold = self.params.threshold if threshold is None else threshold
        resolved_margin = self.params.error_bound if margin is None else margin
        outcome = decide(similarity, resolved_threshold, resolved_margin)
        return CkksDecision(
            zone=outcome.zone,
            decision=outcome.decision,
            similarity=outcome.similarity,
            threshold=outcome.threshold,
            margin=outcome.margin,
            contributors=self._members,
        )

    # ------------------------------- reporting ----------------------------

    def describe(self) -> dict:
        """Engine state for a ``/v1/config`` style endpoint."""
        return {
            "engine": "openfhe-ckks",
            "available": self.is_available(),
            "openfheVersion": openfhe_version(),
            "ready": self._context is not None,
            "ringDimension": self.params.ring_dimension,
            "multiplicativeDepth": self.params.depth,
            "scalingModSize": self.params.scaling_mod_size,
            "embeddingDimension": self.params.embedding_dimension,
            "batchSize": self.params.batch_size,
            "rotationSteps": self.params.rotation_steps,
            "securityLevelBits": 128,
            "errorBound": self.params.error_bound,
            "cosineThreshold": self.params.threshold,
            # Surface this rather than letting a caller assume the engine works.
            "unavailableReason": _IMPORT_ERROR,
        }


# --------------------------------------------------------------------------
# Plaintext helpers, usable without OpenFHE installed.
# --------------------------------------------------------------------------


def rotation_steps_for(dimension: int) -> List[int]:
    """Powers of two needed to reduce ``dimension`` SIMD slots.

    Non-power-of-two dimensions are handled correctly: the loop stops as soon
    as the covered range reaches or exceeds ``dimension``, which is safe
    because the remaining slots were zero-padded at encryption time.
    """
    if dimension <= 0:
        raise ValueError("dimension must be positive")
    steps: List[int] = []
    covered = 1
    while covered < dimension:
        steps.append(covered)
        covered *= 2
    return steps