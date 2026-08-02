"""Translate normalized SLEIGH p-code into Binary Ninja LLIL."""

from __future__ import annotations

from binaryninja.lowlevelil import LLIL_TEMP, LowLevelILLabel

from .decoder import DecodedInstruction, PcodeOperation, Varnode

GPR_NAMES = (
    "zero",
    "at",
    "v0",
    "v1",
    "a0",
    "a1",
    "a2",
    "a3",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "t8",
    "t9",
    "k0",
    "k1",
    "gp",
    "sp",
    "s8",
    "ra",
)

REGISTER_BY_KEY: dict[tuple[int, int], str] = {
    **{(index * 4, 4): name for index, name in enumerate(GPR_NAMES)},
    (0x80, 4): "pc",
    (0x3000, 4): "hi",
    (0x3004, 4): "lo",
}


SUPPORTED_OPCODES = frozenset(
    {
        "COPY",
        "LOAD",
        "STORE",
        "BRANCH",
        "CBRANCH",
        "BRANCHIND",
        "CALL",
        "CALLIND",
        "RETURN",
        "CALLOTHER",
        "CAST",
        "INDIRECT",
        "MULTIEQUAL",
        "INT_EQUAL",
        "INT_NOTEQUAL",
        "INT_SLESS",
        "INT_SLESSEQUAL",
        "INT_LESS",
        "INT_LESSEQUAL",
        "INT_ZEXT",
        "INT_SEXT",
        "INT_ADD",
        "INT_SUB",
        "INT_CARRY",
        "INT_SCARRY",
        "INT_SBORROW",
        "INT_2COMP",
        "INT_NEGATE",
        "INT_XOR",
        "INT_AND",
        "INT_OR",
        "INT_LEFT",
        "INT_RIGHT",
        "INT_SRIGHT",
        "INT_MULT",
        "INT_DIV",
        "INT_SDIV",
        "INT_REM",
        "INT_SREM",
        "BOOL_NEGATE",
        "BOOL_XOR",
        "BOOL_AND",
        "BOOL_OR",
        "PIECE",
        "SUBPIECE",
        "PTRADD",
        "PTRSUB",
        "FLOAT_ADD",
        "FLOAT_SUB",
        "FLOAT_MULT",
        "FLOAT_DIV",
        "FLOAT_NEG",
        "FLOAT_ABS",
        "FLOAT_INT2FLOAT",
        "FLOAT_FLOAT2FLOAT",
        "FLOAT_TRUNC",
        "FLOAT_EQUAL",
        "FLOAT_NOTEQUAL",
        "FLOAT_LESS",
        "FLOAT_LESSEQUAL",
    }
)


def operation_is_supported(opcode: str, mnemonic: str) -> bool:
    """Return whether an opcode is mapped for the current instruction."""

    if opcode == "CALLOTHER":
        return mnemonic in {"break", "syscall"}
    return opcode in SUPPORTED_OPCODES


class PcodeLifter:
    """Lift the p-code for one MIPS16e instruction."""

    def __init__(self, architecture, il, instruction: DecodedInstruction) -> None:
        self.architecture = architecture
        self.il = il
        self.instruction = instruction
        self._emitted_unimplemented = False
        self._local_labels = {}
        self._operation_index = 0

    @staticmethod
    def _temp_for(node: Varnode):
        if node.space == "unique":
            number = node.offset
        else:
            # Unknown SLEIGH registers are modeled as stable temporaries.
            number = 0x01000000 | (node.offset & 0x00FFFFFF)
        return LLIL_TEMP(number)

    def _read(self, node: Varnode):
        if node.space == "const":
            return self.il.const(node.size, node.offset)
        if node.space in {"ram", "code"}:
            return self.il.const_pointer(node.size, node.offset)
        if node.space == "register":
            name = REGISTER_BY_KEY.get((node.offset, node.size))
            if name is not None:
                return self.il.reg(node.size, name)
        return self.il.reg(node.size, self._temp_for(node))

    def _write(self, node: Varnode | None, value) -> None:
        if node is None:
            return
        if node.space == "register":
            name = REGISTER_BY_KEY.get((node.offset, node.size))
            if name == "zero":
                return
            if name is not None:
                self.il.append(self.il.set_reg(node.size, name, value))
                return
        self.il.append(self.il.set_reg(node.size, self._temp_for(node), value))

    def _resize(self, value, source_size: int, target_size: int, signed=False):
        if source_size == target_size:
            return value
        if source_size < target_size:
            if signed:
                return self.il.sign_extend(target_size, value)
            return self.il.zero_extend(target_size, value)
        return self.il.low_part(target_size, value)

    def _pointer(self, node: Varnode):
        if node.space in {"ram", "code"}:
            return self.il.const_pointer(self.architecture.address_size, node.offset)
        return self._read(node)

    def _direct_jump(self, target: int) -> None:
        label = self.il.get_label_for_address(self.architecture, target)
        if label is None:
            self.il.append(
                self.il.jump(
                    self.il.const_pointer(self.architecture.address_size, target)
                )
            )
        else:
            self.il.append(self.il.goto(label))

    def _conditional_jump(self, condition, target: int) -> None:
        true_label = self.il.get_label_for_address(self.architecture, target)
        false_label = self.il.get_label_for_address(
            self.architecture, self.instruction.fallthrough
        )
        synthesize_true = true_label is None
        synthesize_false = false_label is None
        if true_label is None:
            true_label = LowLevelILLabel()
        if false_label is None:
            false_label = LowLevelILLabel()

        self.il.append(self.il.if_expr(condition, true_label, false_label))
        if synthesize_true:
            self.il.mark_label(true_label)
            self.il.append(
                self.il.jump(
                    self.il.const_pointer(self.architecture.address_size, target)
                )
            )
        if synthesize_false:
            self.il.mark_label(false_label)
            self.il.append(
                self.il.jump(
                    self.il.const_pointer(
                        self.architecture.address_size,
                        self.instruction.fallthrough,
                    )
                )
            )

    def _undefined_output(self, op: PcodeOperation) -> None:
        if op.output is not None:
            self._write(op.output, self.il.undefined())
        if not self._emitted_unimplemented:
            self.il.append(self.il.unimplemented())
            self._emitted_unimplemented = True

    @staticmethod
    def _signed_constant(node: Varnode) -> int:
        bits = node.size * 8
        sign = 1 << (bits - 1)
        value = node.offset & ((1 << bits) - 1)
        return value - (1 << bits) if value & sign else value

    def _local_target_index(self, node: Varnode) -> int:
        return self._operation_index + self._signed_constant(node)

    def _prepare_local_labels(self) -> None:
        operation_count = len(self.instruction.operations)
        for index, operation in enumerate(self.instruction.operations):
            if operation.opcode not in {"BRANCH", "CBRANCH"}:
                continue
            if not operation.inputs or operation.inputs[0].space != "const":
                continue
            displacement = self._signed_constant(operation.inputs[0])
            target_index = index + displacement
            if 0 <= target_index <= operation_count:
                self._local_labels.setdefault(target_index, LowLevelILLabel())
                if operation.opcode == "CBRANCH" and index + 1 <= operation_count:
                    self._local_labels.setdefault(index + 1, LowLevelILLabel())

    def _binary(self, op: PcodeOperation, method):
        left = self._read(op.inputs[0])
        right = self._read(op.inputs[1])
        size = op.output.size if op.output is not None else op.inputs[0].size
        self._write(op.output, method(size, left, right))

    def _comparison(self, op: PcodeOperation, method):
        left = self._read(op.inputs[0])
        right = self._read(op.inputs[1])
        self._write(op.output, method(op.inputs[0].size, left, right))

    def _lift_operation(self, op: PcodeOperation) -> None:
        opcode = op.opcode

        if opcode in {"COPY", "CAST", "INDIRECT", "MULTIEQUAL"}:
            value = self._read(op.inputs[0])
            if op.output is not None:
                value = self._resize(
                    value, op.inputs[0].size, op.output.size, signed=False
                )
            self._write(op.output, value)
            return

        if opcode == "LOAD":
            address = self._read(op.inputs[1])
            self._write(op.output, self.il.load(op.output.size, address))
            return

        if opcode == "STORE":
            address = self._read(op.inputs[1])
            value = self._read(op.inputs[2])
            self.il.append(self.il.store(op.inputs[2].size, address, value))
            return

        arithmetic = {
            "INT_ADD": self.il.add,
            "INT_SUB": self.il.sub,
            "INT_MULT": self.il.mult,
            "INT_DIV": self.il.div_unsigned,
            "INT_SDIV": self.il.div_signed,
            "INT_REM": self.il.mod_unsigned,
            "INT_SREM": self.il.mod_signed,
            "INT_XOR": self.il.xor_expr,
            "INT_AND": self.il.and_expr,
            "INT_OR": self.il.or_expr,
            "INT_LEFT": self.il.shift_left,
            "INT_RIGHT": self.il.logical_shift_right,
            "INT_SRIGHT": self.il.arith_shift_right,
            "BOOL_XOR": self.il.xor_expr,
            "BOOL_AND": self.il.and_expr,
            "BOOL_OR": self.il.or_expr,
        }
        if opcode in arithmetic:
            self._binary(op, arithmetic[opcode])
            return

        comparisons = {
            "INT_EQUAL": self.il.compare_equal,
            "INT_NOTEQUAL": self.il.compare_not_equal,
            "INT_SLESS": self.il.compare_signed_less_than,
            "INT_SLESSEQUAL": self.il.compare_signed_less_equal,
            "INT_LESS": self.il.compare_unsigned_less_than,
            "INT_LESSEQUAL": self.il.compare_unsigned_less_equal,
        }
        if opcode in comparisons:
            self._comparison(op, comparisons[opcode])
            return

        if opcode in {"INT_ZEXT", "INT_SEXT"}:
            value = self._read(op.inputs[0])
            signed = opcode == "INT_SEXT"
            self._write(
                op.output,
                self._resize(value, op.inputs[0].size, op.output.size, signed=signed),
            )
            return

        if opcode == "INT_2COMP":
            value = self._read(op.inputs[0])
            self._write(op.output, self.il.neg_expr(op.output.size, value))
            return

        if opcode == "INT_NEGATE":
            value = self._read(op.inputs[0])
            self._write(op.output, self.il.not_expr(op.output.size, value))
            return

        if opcode == "BOOL_NEGATE":
            value = self._read(op.inputs[0])
            zero = self.il.const(op.inputs[0].size, 0)
            self._write(
                op.output,
                self.il.compare_equal(op.inputs[0].size, value, zero),
            )
            return

        if opcode == "INT_CARRY":
            left = self._read(op.inputs[0])
            right = self._read(op.inputs[1])
            size = op.inputs[0].size
            result = self.il.add(size, left, right)
            self._write(
                op.output,
                self.il.compare_unsigned_less_than(size, result, left),
            )
            return

        if opcode in {"INT_SCARRY", "INT_SBORROW"}:
            left = self._read(op.inputs[0])
            right = self._read(op.inputs[1])
            size = op.inputs[0].size
            if opcode == "INT_SCARRY":
                result = self.il.add(size, left, right)
                overflow_bits = self.il.and_expr(
                    size,
                    self.il.xor_expr(size, left, result),
                    self.il.xor_expr(size, right, result),
                )
            else:
                result = self.il.sub(size, left, right)
                overflow_bits = self.il.and_expr(
                    size,
                    self.il.xor_expr(size, left, right),
                    self.il.xor_expr(size, left, result),
                )
            self._write(
                op.output,
                self.il.test_bit(
                    size,
                    overflow_bits,
                    self.il.const(size, size * 8 - 1),
                ),
            )
            return

        if opcode == "PIECE":
            high = self._read(op.inputs[0])
            low = self._read(op.inputs[1])
            size = op.output.size
            high = self._resize(high, op.inputs[0].size, size)
            low = self._resize(low, op.inputs[1].size, size)
            high = self.il.shift_left(
                size, high, self.il.const(size, op.inputs[1].size * 8)
            )
            self._write(op.output, self.il.or_expr(size, high, low))
            return

        if opcode == "SUBPIECE":
            value = self._read(op.inputs[0])
            byte_offset = op.inputs[1].offset
            shifted = self.il.logical_shift_right(
                op.inputs[0].size,
                value,
                self.il.const(op.inputs[0].size, byte_offset * 8),
            )
            self._write(op.output, self.il.low_part(op.output.size, shifted))
            return

        if opcode == "PTRADD":
            base = self._read(op.inputs[0])
            index = self._read(op.inputs[1])
            element_size = self._read(op.inputs[2])
            size = op.output.size
            scaled = self.il.mult(size, index, element_size)
            self._write(op.output, self.il.add(size, base, scaled))
            return

        if opcode == "PTRSUB":
            self._binary(op, self.il.add)
            return

        float_binary = {
            "FLOAT_ADD": self.il.float_add,
            "FLOAT_SUB": self.il.float_sub,
            "FLOAT_MULT": self.il.float_mult,
            "FLOAT_DIV": self.il.float_div,
        }
        if opcode in float_binary:
            self._binary(op, float_binary[opcode])
            return

        if opcode in {"FLOAT_NEG", "FLOAT_ABS"}:
            method = self.il.float_neg if opcode == "FLOAT_NEG" else self.il.float_abs
            self._write(op.output, method(op.output.size, self._read(op.inputs[0])))
            return

        if opcode == "FLOAT_INT2FLOAT":
            self._write(
                op.output,
                self.il.int_to_float(op.output.size, self._read(op.inputs[0])),
            )
            return

        if opcode == "FLOAT_FLOAT2FLOAT":
            self._write(
                op.output,
                self.il.float_convert(op.output.size, self._read(op.inputs[0])),
            )
            return

        if opcode == "FLOAT_TRUNC":
            self._write(
                op.output,
                self.il.float_trunc(op.output.size, self._read(op.inputs[0])),
            )
            return

        float_comparisons = {
            "FLOAT_EQUAL": self.il.float_compare_equal,
            "FLOAT_NOTEQUAL": self.il.float_compare_not_equal,
            "FLOAT_LESS": self.il.float_compare_less_than,
            "FLOAT_LESSEQUAL": self.il.float_compare_less_equal,
        }
        if opcode in float_comparisons:
            self._comparison(op, float_comparisons[opcode])
            return

        if opcode == "BRANCH":
            target = op.inputs[0]
            if target.space in {"ram", "code"}:
                self._direct_jump(target.offset)
            elif target.space == "const":
                label = self._local_labels.get(self._local_target_index(target))
                if label is None:
                    self._undefined_output(op)
                else:
                    self.il.append(self.il.goto(label))
            else:
                self.il.append(self.il.jump(self._pointer(target)))
            return

        if opcode == "CBRANCH":
            target = op.inputs[0]
            condition = self._read(op.inputs[1])
            if target.space in {"ram", "code"}:
                self._conditional_jump(condition, target.offset)
            elif target.space == "const":
                true_label = self._local_labels.get(self._local_target_index(target))
                false_label = self._local_labels.get(self._operation_index + 1)
                if true_label is None or false_label is None:
                    self._undefined_output(op)
                else:
                    self.il.append(
                        self.il.if_expr(condition, true_label, false_label)
                    )
            else:
                self._undefined_output(op)
            return

        if opcode == "BRANCHIND":
            self.il.append(self.il.jump(self._pointer(op.inputs[0])))
            return

        if opcode == "CALL":
            self.il.append(self.il.call(self._pointer(op.inputs[0])))
            return

        if opcode == "CALLIND":
            self.il.append(self.il.call(self._pointer(op.inputs[0])))
            return

        if opcode == "RETURN":
            is_return_register = (
                self.instruction.mnemonic in {"jr", "jrc"}
                and "ra" in self.instruction.operands
            )
            if is_return_register:
                target = self.il.reg(self.architecture.address_size, "ra")
            else:
                target = self._pointer(op.inputs[0])
            self.il.append(self.il.ret(target))
            return

        if opcode == "CALLOTHER":
            if self.instruction.mnemonic == "syscall":
                self.il.append(self.il.system_call())
                return
            if self.instruction.mnemonic == "break":
                value = 0
                if len(op.inputs) > 1 and op.inputs[1].space == "const":
                    value = op.inputs[1].offset
                self.il.append(self.il.trap(value))
                return

        self._undefined_output(op)

    def lift(self) -> None:
        self._prepare_local_labels()
        for index, operation in enumerate(self.instruction.operations):
            self._operation_index = index
            label = self._local_labels.get(index)
            if label is not None:
                self.il.mark_label(label)
            self._lift_operation(operation)
        final_label = self._local_labels.get(len(self.instruction.operations))
        if final_label is not None:
            self.il.mark_label(final_label)
        if not self.instruction.operations:
            self.il.append(self.il.nop())
