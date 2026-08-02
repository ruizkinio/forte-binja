"""Thread-safe MIPS16e decoding backed by pypcode.

This module deliberately has no Binary Ninja dependency.  Keeping the decoder
standalone makes it possible to exercise the instruction and control-flow
logic in normal CI runners.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from threading import local

try:
    from pypcode import Context
except ImportError as exc:  # pragma: no cover - exercised by Binary Ninja UI
    Context = None  # type: ignore[assignment]
    _IMPORT_ERROR: ImportError | None = exc
else:
    _IMPORT_ERROR = None


MIPS16_BE_LANGUAGE = "MIPS:BE:32:default"
MIPS16_LE_LANGUAGE = "MIPS:LE:32:default"
MAX_INSTRUCTION_LENGTH = 4
MAX_DECODE_WINDOW = 8


class DecoderUnavailable(RuntimeError):
    """Raised when Forte's pypcode runtime is unavailable."""


class DecodeError(ValueError):
    """Raised when a byte sequence is not a valid MIPS16e instruction."""


@dataclass(frozen=True)
class Varnode:
    """A serializable p-code varnode."""

    space: str
    offset: int
    size: int


@dataclass(frozen=True)
class PcodeOperation:
    """A serializable p-code operation."""

    opcode: str
    inputs: tuple[Varnode, ...]
    output: Varnode | None


@dataclass(frozen=True)
class FlowEdge:
    """Control-flow metadata derived from p-code."""

    kind: str
    target: int | None = None


@dataclass(frozen=True)
class DecodedInstruction:
    """One decoded MIPS16e instruction and its normalized p-code."""

    address: int
    length: int
    mnemonic: str
    operands: str
    operations: tuple[PcodeOperation, ...]
    edges: tuple[FlowEdge, ...]
    delay_slots: int
    fallthrough: int
    delay_semantics_stripped: bool

    @property
    def branch_targets(self) -> tuple[int, ...]:
        return tuple(edge.target for edge in self.edges if edge.target is not None)


_thread_state = local()


def dependency_error() -> ImportError | None:
    """Return the captured pypcode import failure, if one occurred."""

    return _IMPORT_ERROR


def _context(language_id: str):
    if Context is None:
        raise DecoderUnavailable(
            "Forte requires pypcode 2.x. Install the plugin through Binary "
            "Ninja's Plugin Manager or run `python -m pip install pypcode` "
            "in Binary Ninja's Python environment."
        ) from _IMPORT_ERROR

    contexts = getattr(_thread_state, "contexts", None)
    if contexts is None:
        contexts = {}
        _thread_state.contexts = contexts

    context = contexts.get(language_id)
    if context is None:
        context = Context(language_id)
        # Ghidra's MIPS SLEIGH specification uses ISA_MODE=1 for MIPS16.
        context.setVariableDefault("ISA_MODE", 1)
        contexts[language_id] = context
    return context


def _varnode(node) -> Varnode:
    return Varnode(node.space.name, int(node.offset), int(node.size))


def _operation(op) -> PcodeOperation:
    opcode = str(op.opcode).rsplit(".", 1)[-1]
    output = None if op.output is None else _varnode(op.output)
    return PcodeOperation(opcode, tuple(_varnode(item) for item in op.inputs), output)


def _translate(context, data: bytes, address: int) -> tuple[PcodeOperation, ...]:
    translation = context.translate(data, address, max_instructions=1)
    return tuple(_operation(op) for op in translation.ops)


def _disassemble_one(context, data: bytes, address: int):
    if len(data) < 2:
        raise DecodeError(f"not enough bytes to decode an instruction at {address:#x}")
    try:
        instructions = context.disassemble(
            data, address, max_instructions=1
        ).instructions
    except Exception as exc:
        message = f"invalid MIPS16e instruction at {address:#x}: {exc}"
        raise DecodeError(message) from exc
    if not instructions:
        raise DecodeError(f"invalid MIPS16e instruction at {address:#x}")
    return instructions[0]


def _operations_equivalent(left: PcodeOperation, right: PcodeOperation) -> bool:
    if left.opcode != right.opcode or left.output != right.output:
        return False

    left_inputs = left.inputs
    right_inputs = right.inputs
    if left.opcode in {"LOAD", "STORE"}:
        # SLEIGH represents the address-space selector as an opaque constant.
        # Its numeric value is process-specific, so it must not participate in
        # equivalence checks.
        left_inputs = left_inputs[1:]
        right_inputs = right_inputs[1:]
    return left_inputs == right_inputs


def _remove_subsequence(
    operations: tuple[PcodeOperation, ...],
    subsequence: tuple[PcodeOperation, ...],
) -> tuple[tuple[PcodeOperation, ...], bool]:
    if not subsequence:
        return operations, True

    upper = len(operations) - len(subsequence) + 1
    for start in range(max(upper, 0)):
        candidate = operations[start : start + len(subsequence)]
        if all(
            _operations_equivalent(left, right)
            for left, right in zip(candidate, subsequence, strict=True)
        ):
            return operations[:start] + operations[start + len(subsequence) :], True
    return operations, False


def _external_target(node: Varnode) -> int | None:
    if node.space in {"ram", "code"}:
        return node.offset
    return None


def _derive_edges(
    operations: Iterable[PcodeOperation],
    fallthrough: int,
) -> tuple[FlowEdge, ...]:
    edges = []
    for op in operations:
        target = _external_target(op.inputs[0]) if op.inputs else None
        if op.opcode == "BRANCH":
            if target is not None:
                edges.append(FlowEdge("unconditional", target))
        elif op.opcode == "CBRANCH":
            if target is not None:
                edges.append(FlowEdge("true", target))
                edges.append(FlowEdge("false", fallthrough))
        elif op.opcode == "BRANCHIND":
            edges.append(FlowEdge("indirect"))
        elif op.opcode == "CALL":
            edges.append(FlowEdge("call", target))
        elif op.opcode == "CALLIND":
            edges.append(FlowEdge("indirect_call"))
        elif op.opcode == "RETURN":
            edges.append(FlowEdge("return"))
    return tuple(edges)


@lru_cache(maxsize=32768)
def _decode_cached(
    language_id: str,
    data: bytes,
    address: int,
) -> DecodedInstruction:
    context = _context(language_id)
    instruction = _disassemble_one(context, data, address)
    length = int(instruction.length)
    if length not in (2, 4):
        raise DecodeError(
            f"unexpected MIPS16e instruction length {length} at {address:#x}"
        )

    raw_operations = _translate(context, data, address)
    imark = next((op for op in raw_operations if op.opcode == "IMARK"), None)
    delay_slots = max(0, len(imark.inputs) - 1) if imark is not None else 0

    operations = tuple(op for op in raw_operations if op.opcode != "IMARK")
    cursor = length
    stripped = True
    for _ in range(delay_slots):
        if cursor >= len(data):
            stripped = False
            break
        delay_address = address + cursor
        delay_instruction = _disassemble_one(context, data[cursor:], delay_address)
        delay_operations = tuple(
            op
            for op in _translate(context, data[cursor:], delay_address)
            if op.opcode != "IMARK"
        )
        operations, found = _remove_subsequence(operations, delay_operations)
        stripped = stripped and found
        cursor += int(delay_instruction.length)

    # When a SLEIGH specification changes and delay-slot subtraction cannot be
    # proven, retain only control-flow p-code. Binary Ninja will lift the delay
    # instruction separately, which is safer than duplicating side effects.
    if delay_slots and not stripped:
        operations = tuple(
            op
            for op in operations
            if op.opcode
            in {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN"}
        )

    fallthrough = address + cursor
    return DecodedInstruction(
        address=address,
        length=length,
        mnemonic=str(instruction.mnem),
        operands=str(instruction.body),
        operations=operations,
        edges=_derive_edges(operations, fallthrough),
        delay_slots=delay_slots,
        fallthrough=fallthrough,
        delay_semantics_stripped=stripped,
    )


class Mips16Decoder:
    """Decode one endian variant of MIPS16e."""

    def __init__(self, language_id: str) -> None:
        if language_id not in {MIPS16_BE_LANGUAGE, MIPS16_LE_LANGUAGE}:
            raise ValueError(f"unsupported pypcode language: {language_id}")
        self.language_id = language_id

    def decode(self, data: bytes, address: int) -> DecodedInstruction:
        window = bytes(data[:MAX_DECODE_WINDOW])
        return _decode_cached(self.language_id, window, int(address))

    @staticmethod
    def clear_cache() -> None:
        _decode_cached.cache_clear()
