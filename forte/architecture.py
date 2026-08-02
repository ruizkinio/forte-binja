"""Binary Ninja architecture definitions for MIPS16e."""

from __future__ import annotations

import re

from binaryninja import (
    Architecture,
    ArchitectureHook,
    BranchType,
    Endianness,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    RegisterInfo,
    log_error,
)

from .decoder import (
    MIPS16_BE_LANGUAGE,
    MIPS16_LE_LANGUAGE,
    DecodeError,
    Mips16Decoder,
)
from .lifter import GPR_NAMES, PcodeLifter

MIPS16_BE_ARCH = "mips16e"
MIPS16_LE_ARCH = "mips16el"

REGISTER_NAMES = GPR_NAMES + ("pc", "hi", "lo")
REGISTER_SET = frozenset(REGISTER_NAMES)
REGISTER_MAP = {name: RegisterInfo(name, 4) for name in REGISTER_NAMES}

_OPERAND_RE = re.compile(
    r"(0x[0-9a-fA-F]+|-?\d+|[A-Za-z_][A-Za-z0-9_]*|,\s*|\(|\)|\s+|.)"
)


def _tokens_for_instruction(decoded) -> list[InstructionTextToken]:
    tokens = [
        InstructionTextToken(
            InstructionTextTokenType.InstructionToken,
            f"{decoded.mnemonic:<8}",
        )
    ]
    targets = set(decoded.branch_targets)
    for part in _OPERAND_RE.findall(decoded.operands):
        if not part:
            continue
        if part.startswith(","):
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ", "
                )
            )
            continue
        if part == "(":
            token_type = InstructionTextTokenType.BeginMemoryOperandToken
            tokens.append(InstructionTextToken(token_type, part))
            continue
        if part == ")":
            token_type = InstructionTextTokenType.EndMemoryOperandToken
            tokens.append(InstructionTextToken(token_type, part))
            continue
        if part in REGISTER_SET:
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.RegisterToken, part)
            )
            continue
        if part.startswith("0x") or part.lstrip("-").isdigit():
            try:
                value = int(part, 0)
            except ValueError:
                value = 0
            token_type = (
                InstructionTextTokenType.PossibleAddressToken
                if value in targets
                else InstructionTextTokenType.IntegerToken
            )
            tokens.append(InstructionTextToken(token_type, part, value))
            continue
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, part))
    return tokens


class _Mips16Architecture(Architecture):
    address_size = 4
    default_int_size = 4
    instr_alignment = 2
    # Four bytes for the current instruction plus up to four bytes for a
    # SLEIGH-expanded delay slot.
    max_instr_length = 8
    opcode_display_length = 4
    regs = REGISTER_MAP
    stack_pointer = "sp"
    link_reg = "ra"
    global_regs = ["gp"]
    system_regs = ["pc", "hi", "lo"]
    language_id = ""
    base_arch_name = ""

    def __init__(self):
        self._decoder = Mips16Decoder(self.language_id)
        super().__init__()

    def get_associated_arch_by_address(self, addr: int):
        # The low bit in ELF symbols is an ISA-mode tag, not part of the
        # instruction address.
        return self, addr & ~1

    def _decode(self, data: bytes, addr: int):
        try:
            return self._decoder.decode(data, addr)
        except DecodeError:
            return None

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        decoded = self._decode(data, addr)
        if decoded is None:
            return None

        result = InstructionInfo()
        result.length = decoded.length
        result.branch_delay = decoded.delay_slots

        base_arch = Architecture.get(self.base_arch_name)
        for edge in decoded.edges:
            if edge.kind == "unconditional" and edge.target is not None:
                result.add_branch(BranchType.UnconditionalBranch, edge.target)
            elif edge.kind == "true" and edge.target is not None:
                result.add_branch(BranchType.TrueBranch, edge.target)
            elif edge.kind == "false" and edge.target is not None:
                result.add_branch(BranchType.FalseBranch, edge.target)
            elif edge.kind == "call" and edge.target is not None:
                if decoded.mnemonic == "jalx" and base_arch is not None:
                    result.add_branch(
                        BranchType.CallDestination, edge.target & ~1, base_arch
                    )
                else:
                    result.add_branch(BranchType.CallDestination, edge.target & ~1)
            elif edge.kind == "indirect":
                result.arch_transition_by_target_addr = True
                result.add_branch(BranchType.IndirectBranch)
            elif edge.kind == "indirect_call":
                result.arch_transition_by_target_addr = True
            elif edge.kind == "return":
                result.arch_transition_by_target_addr = True
                result.add_branch(BranchType.FunctionReturn)
        return result

    def get_instruction_text(
        self, data: bytes, addr: int
    ) -> tuple[list[InstructionTextToken], int] | None:
        decoded = self._decode(data, addr)
        if decoded is None:
            return None
        return _tokens_for_instruction(decoded), decoded.length

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = self._decode(data, addr)
        if decoded is None:
            return None
        try:
            PcodeLifter(self, il, decoded).lift()
        except Exception as exc:  # Never let a lifter bug abort whole-file analysis.
            log_error(
                f"Forte: LLIL failure at {addr:#x} "
                f"({decoded.mnemonic} {decoded.operands}): {exc}"
            )
            il.append(il.unimplemented())
        return decoded.length


class Mips16eArchitecture(_Mips16Architecture):
    name = MIPS16_BE_ARCH
    endianness = Endianness.BigEndian
    language_id = MIPS16_BE_LANGUAGE
    base_arch_name = "mips32"


class Mips16elArchitecture(_Mips16Architecture):
    name = MIPS16_LE_ARCH
    endianness = Endianness.LittleEndian
    language_id = MIPS16_LE_LANGUAGE
    base_arch_name = "mipsel32"


class Mips32ModeHook(ArchitectureHook):
    """Route odd MIPS ELF addresses into Forte's big-endian architecture."""

    def get_associated_arch_by_address(self, addr: int):
        if addr & 1:
            return Architecture[MIPS16_BE_ARCH], addr & ~1
        return super().get_associated_arch_by_address(addr)


class Mipsel32ModeHook(ArchitectureHook):
    """Route odd MIPS ELF addresses into Forte's little-endian architecture."""

    def get_associated_arch_by_address(self, addr: int):
        if addr & 1:
            return Architecture[MIPS16_LE_ARCH], addr & ~1
        return super().get_associated_arch_by_address(addr)
