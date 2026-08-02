from forte.decoder import (
    MIPS16_BE_LANGUAGE,
    MIPS16_LE_LANGUAGE,
    Mips16Decoder,
)

EXPECTED_SEQUENCE = (
    ("slti", "a0, 0x3", 2),
    ("save", "0x20,ra", 2),
    ("bteqz", "0x401ca2", 2),
    ("jal", "0x402fe0", 4),
    ("nop", "", 2),
    ("b", "0x401cc0", 2),
)

BIG_ENDIAN_SEQUENCE = bytes.fromhex("540364c460041a000bf86500100f")
LITTLE_ENDIAN_SEQUENCE = bytes.fromhex("0354c4640460001af80b00650f10")


def decode_sequence(language, blob):
    decoder = Mips16Decoder(language)
    address = 0x401C94
    offset = 0
    instructions = []
    for _ in EXPECTED_SEQUENCE:
        decoded = decoder.decode(blob[offset:], address + offset)
        instructions.append((decoded.mnemonic, decoded.operands, decoded.length))
        offset += decoded.length
    return tuple(instructions)


def test_big_endian_instruction_sequence():
    assert decode_sequence(MIPS16_BE_LANGUAGE, BIG_ENDIAN_SEQUENCE) == EXPECTED_SEQUENCE


def test_little_endian_instruction_sequence():
    assert (
        decode_sequence(MIPS16_LE_LANGUAGE, LITTLE_ENDIAN_SEQUENCE)
        == EXPECTED_SEQUENCE
    )


def test_conditional_branch_edges():
    decoder = Mips16Decoder(MIPS16_BE_LANGUAGE)
    decoded = decoder.decode(bytes.fromhex("60041a000bf8"), 0x401C98)
    assert decoded.mnemonic == "bteqz"
    assert decoded.delay_slots == 0
    assert decoded.fallthrough == 0x401C9A
    assert decoded.edges == (
        # The target comes from SLEIGH p-code rather than operand parsing.
        type(decoded.edges[0])("true", 0x401CA2),
        type(decoded.edges[0])("false", 0x401C9A),
    )


def test_call_delay_slot_is_not_lifted_twice():
    decoder = Mips16Decoder(MIPS16_BE_LANGUAGE)
    # jal 0x410670; li a0, 0x12
    decoded = decoder.decode(bytes.fromhex("1a00419c6c126d01"), 0x401CA4)
    assert decoded.mnemonic == "jal"
    assert decoded.delay_slots == 1
    assert decoded.fallthrough == 0x401CAA
    assert decoded.delay_semantics_stripped
    assert [operation.opcode for operation in decoded.operations] == [
        "INT_OR",
        "CALL",
    ]
    assert all(
        operation.output is None
        or not (
            operation.output.space == "register"
            and operation.output.offset == 0x10
        )
        for operation in decoded.operations
    )


def test_return_delay_slot_is_not_lifted_twice():
    decoder = Mips16Decoder(MIPS16_BE_LANGUAGE)
    # jr ra; sw v0, 0(v1)
    decoded = decoder.decode(bytes.fromhex("e820db400040dbbc"), 0x401CD8)
    assert decoded.mnemonic == "jr"
    assert decoded.delay_slots == 1
    assert decoded.fallthrough == 0x401CDC
    assert decoded.delay_semantics_stripped
    assert "STORE" not in [operation.opcode for operation in decoded.operations]
    assert decoded.edges[-1].kind == "return"


def test_internal_pcode_branch_is_not_exposed_as_machine_control_flow():
    decoder = Mips16Decoder(MIPS16_BE_LANGUAGE)
    decoded = decoder.decode(bytes.fromhex("eabb2d01e8e5"), 0x403510)
    assert decoded.mnemonic == "divu"
    assert decoded.edges == ()
    branch = next(op for op in decoded.operations if op.opcode == "CBRANCH")
    assert branch.inputs[0].space == "const"
    assert branch.inputs[0].offset == 3
