"""Register Forte architectures, ABI metadata, platforms, hooks, and commands."""

from __future__ import annotations

from binaryninja import Architecture, CallingConvention, Platform, log_error, log_info

from .architecture import (
    Mips16eArchitecture,
    Mips16elArchitecture,
    Mips32ModeHook,
    Mipsel32ModeHook,
)
from .commands import BIG_PLATFORM, LITTLE_PLATFORM, register_commands
from .decoder import dependency_error


class MipsO32CallingConvention(CallingConvention):
    caller_saved_regs = [
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
        "t8",
        "t9",
        "ra",
        "hi",
        "lo",
    ]
    callee_saved_regs = [
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
        "gp",
        "sp",
    ]
    int_arg_regs = ["a0", "a1", "a2", "a3"]
    int_return_reg = "v0"
    high_int_return_reg = "v1"
    global_pointer_regs = ["gp"]


class LinuxMips16ePlatform(Platform):
    name = BIG_PLATFORM


class LinuxMips16elPlatform(Platform):
    name = LITTLE_PLATFORM


_REGISTERED = False
_HOOKS = []
_PLATFORMS = []
_CALLING_CONVENTIONS = []


def _register_architecture(architecture_class):
    if architecture_class.name not in Architecture:
        return architecture_class.register()
    return Architecture[architecture_class.name]


def _register_platform(
    arch,
    platform_class,
    platform_name: str,
    base_arch_name: str,
    base_platform_name: str,
):
    existing = Platform.get(platform_name)
    if existing is not None:
        return existing

    calling_convention = MipsO32CallingConvention(arch, "o32")
    arch.register_calling_convention(calling_convention)
    arch.default_calling_convention = calling_convention
    arch.cdecl_calling_convention = calling_convention

    platform = platform_class(arch)
    platform.register_calling_convention(calling_convention)
    platform.default_calling_convention = calling_convention
    platform.cdecl_calling_convention = calling_convention
    platform.register("linux")

    base_arch = Architecture.get(base_arch_name)
    base_platform = Platform.get(base_platform_name)
    if base_arch is not None and base_platform is not None:
        base_platform.add_related_platform(arch, platform)
        platform.add_related_platform(base_arch, base_platform)

    _CALLING_CONVENTIONS.append(calling_convention)
    _PLATFORMS.append(platform)
    return platform


def register() -> bool:
    global _REGISTERED
    if _REGISTERED:
        return True

    error = dependency_error()
    if error is not None:
        log_error(
            "Forte was not loaded because pypcode is unavailable. Install "
            "`pypcode>=2,<3` in Binary Ninja's Python environment. "
            f"Import error: {error}"
        )
        return False

    big_arch = _register_architecture(Mips16eArchitecture)
    little_arch = _register_architecture(Mips16elArchitecture)
    _register_platform(
        big_arch,
        LinuxMips16ePlatform,
        BIG_PLATFORM,
        "mips32",
        "linux-mips",
    )
    _register_platform(
        little_arch,
        LinuxMips16elPlatform,
        LITTLE_PLATFORM,
        "mipsel32",
        "linux-mipsel",
    )

    if "mips32" in Architecture:
        hook = Mips32ModeHook(Architecture["mips32"])
        hook.register()
        _HOOKS.append(hook)
    if "mipsel32" in Architecture:
        hook = Mipsel32ModeHook(Architecture["mipsel32"])
        hook.register()
        _HOOKS.append(hook)

    register_commands()
    _REGISTERED = True
    log_info(
        "Forte: registered MIPS16e big/little-endian architectures, Linux "
        "o32 platforms, mixed-mode MIPS hooks, and analysis commands."
    )
    return True
