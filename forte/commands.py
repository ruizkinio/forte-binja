"""User-facing Binary Ninja commands for Forte."""

from __future__ import annotations

from collections import Counter

from binaryninja import (
    Platform,
    PluginCommand,
    SymbolType,
    log_info,
    show_plain_text_report,
)

from .architecture import MIPS16_BE_ARCH, MIPS16_LE_ARCH
from .decoder import (
    MIPS16_BE_LANGUAGE,
    MIPS16_LE_LANGUAGE,
    DecodeError,
    Mips16Decoder,
)
from .lifter import operation_is_supported

BIG_PLATFORM = "linux-mips16e"
LITTLE_PLATFORM = "linux-mips16el"

_COMMANDS_REGISTERED = False


def _mode_for_view(bv):
    name = bv.arch.name if bv.arch is not None else ""
    if "mipsel" in name or name == MIPS16_LE_ARCH:
        return MIPS16_LE_ARCH, LITTLE_PLATFORM, MIPS16_LE_LANGUAGE
    return MIPS16_BE_ARCH, BIG_PLATFORM, MIPS16_BE_LANGUAGE


def _platform_for_view(bv):
    _, platform_name, _ = _mode_for_view(bv)
    return Platform.get(platform_name)


def analyze_current_address(bv, address):
    platform = _platform_for_view(bv)
    if platform is None:
        show_plain_text_report(
            "Forte",
            "Forte's Linux MIPS16e platform is not registered. Restart Binary "
            "Ninja and check the log for a dependency error.",
        )
        return
    canonical = int(address) & ~1
    function = bv.create_user_function(canonical, platform)
    if function is None:
        message = f"Binary Ninja did not create a function at {canonical:#x}."
    else:
        message = (
            f"Created {function.arch.name} function {function.name} at "
            f"{canonical:#x}."
        )
    bv.update_analysis()
    log_info(f"Forte: {message}")


def seed_odd_elf_symbols(bv):
    platform = _platform_for_view(bv)
    if platform is None:
        show_plain_text_report(
            "Forte",
            "Forte's Linux MIPS16e platform is not registered. Restart Binary "
            "Ninja and check the log for a dependency error.",
        )
        return

    symbols = sorted(
        (
            symbol
            for symbol in bv.get_symbols()
            if symbol.type == SymbolType.FunctionSymbol and symbol.address & 1
        ),
        key=lambda symbol: symbol.address,
    )
    created = []
    existing = []
    for symbol in symbols:
        canonical = symbol.address & ~1
        function = next(
            (
                item
                for item in bv.get_functions_at(canonical)
                if item.arch.name in {MIPS16_BE_ARCH, MIPS16_LE_ARCH}
            ),
            None,
        )
        if function is None:
            function = bv.create_user_function(canonical, platform)
            if function is not None:
                try:
                    function.name = symbol.name
                except Exception:
                    pass
                created.append((canonical, symbol.name))
        else:
            existing.append((canonical, symbol.name))

    bv.update_analysis()
    lines = [
        "Seeded MIPS16e analysis from ELF function symbols whose low bit marks "
        "compressed mode.",
        "",
        f"Created: {len(created)}",
        f"Already present: {len(existing)}",
        f"Odd function symbols found: {len(symbols)}",
    ]
    if created:
        lines.extend(
            ["", "Created functions:"]
            + [f"  {address:#x}  {name}" for address, name in created]
        )
    lines.extend(
        [
            "",
            "Forte does not delete existing functions. For the cleanest mixed-"
            "mode analysis, install Forte before opening the original ELF in a "
            "new Binary Ninja database.",
        ]
    )
    show_plain_text_report("Forte — MIPS16e symbol seeding", "\n".join(lines))


def run_self_test(_bv):
    fixtures = (
        (
            MIPS16_BE_LANGUAGE,
            bytes.fromhex("540364c460041a000bf86500100f"),
        ),
        (
            MIPS16_LE_LANGUAGE,
            bytes.fromhex("0354c4640460001af80b00650f10"),
        ),
    )
    expected = (
        ("slti", "a0, 0x3", 2),
        ("save", "0x20,ra", 2),
        ("bteqz", "0x401ca2", 2),
        ("jal", "0x402fe0", 4),
        ("nop", "", 2),
        ("b", "0x401cc0", 2),
    )
    lines = []
    failures = []
    for language, blob in fixtures:
        decoder = Mips16Decoder(language)
        offset = 0
        actual = []
        for _ in expected:
            decoded = decoder.decode(blob[offset:], 0x401C94 + offset)
            actual.append((decoded.mnemonic, decoded.operands, decoded.length))
            offset += decoded.length
        passed = tuple(actual) == expected
        lines.append(f"{language}: {'PASS' if passed else 'FAIL'}")
        if not passed:
            failures.append((language, actual))

    lines.extend(
        [
            "",
            "Checks:",
            "  big-endian instruction decoding",
            "  little-endian instruction decoding",
            "  16-bit and extended 32-bit instruction lengths",
            "  direct branch and call targets",
            "  delay-slot separation",
        ]
    )
    if failures:
        lines.extend(["", f"Failures: {failures!r}"])
    else:
        lines.extend(["", "All decoder checks passed."])
    show_plain_text_report("Forte — self-test", "\n".join(lines))


def report_lifter_coverage(bv):
    addresses = {}
    for function in bv.functions:
        if function.arch.name not in {MIPS16_BE_ARCH, MIPS16_LE_ARCH}:
            continue
        language = (
            MIPS16_LE_LANGUAGE
            if function.arch.name == MIPS16_LE_ARCH
            else MIPS16_BE_LANGUAGE
        )
        for _tokens, address in function.instructions:
            addresses[(language, int(address))] = None

    if not addresses:
        show_plain_text_report(
            "Forte — LLIL coverage",
            "No Forte MIPS16e functions are present yet. Reopen the ELF after "
            "installing Forte, run “Seed Functions from Odd ELF Symbols”, or "
            "create a MIPS16e function at the current address.",
        )
        return

    counts = Counter()
    failures = []
    for language, address in sorted(addresses):
        decoder = Mips16Decoder(language)
        try:
            decoded = decoder.decode(bv.read(address, 8), address)
        except DecodeError as exc:
            failures.append(f"{address:#x}: {exc}")
            continue
        counts.update(op.opcode for op in decoded.operations)

    unsupported = Counter()
    supported_count = 0
    for language, address in sorted(addresses):
        decoder = Mips16Decoder(language)
        try:
            decoded = decoder.decode(bv.read(address, 8), address)
        except DecodeError:
            continue
        for operation in decoded.operations:
            if operation_is_supported(operation.opcode, decoded.mnemonic):
                supported_count += 1
            else:
                unsupported[operation.opcode] += 1
    total = sum(counts.values())
    percent = 100.0 if total == 0 else 100.0 * supported_count / total
    lines = [
        f"Instructions inspected: {len(addresses)}",
        f"P-code operations: {total}",
        f"Mapped to LLIL: {supported_count} ({percent:.2f}%)",
        f"Decode failures: {len(failures)}",
        "",
        "Operation counts:",
    ]
    lines.extend(f"  {opcode:<18} {count}" for opcode, count in sorted(counts.items()))
    if unsupported:
        lines.extend(["", "Unsupported operations:"])
        lines.extend(
            f"  {opcode:<18} {count}" for opcode, count in unsupported.items()
        )
    if failures:
        lines.extend(["", "Decode failures:"] + [f"  {line}" for line in failures])
    show_plain_text_report("Forte — LLIL coverage", "\n".join(lines))


def register_commands() -> None:
    global _COMMANDS_REGISTERED
    if _COMMANDS_REGISTERED:
        return
    PluginCommand.register_for_address(
        "Forte\\Analyze MIPS16e Function Here",
        "Create a Forte MIPS16e function at the selected address.",
        analyze_current_address,
    )
    PluginCommand.register(
        "Forte\\Seed Functions from Odd ELF Symbols",
        "Create MIPS16e functions for ELF symbols tagged by an odd address.",
        seed_odd_elf_symbols,
    )
    PluginCommand.register(
        "Forte\\Report LLIL Coverage",
        "Measure Forte's p-code-to-LLIL coverage in current MIPS16e functions.",
        report_lifter_coverage,
    )
    PluginCommand.register(
        "Forte\\Run Decoder Self-Test",
        "Run Forte's endian, length, branch, and delay-slot decoder checks.",
        run_self_test,
    )
    _COMMANDS_REGISTERED = True
