# Contributing to Forte

Thank you for helping make MIPS16e firmware analysis better in Binary Ninja.

## Before opening an issue

- Confirm the bytes decode in MIPS16e mode, not ordinary MIPS32.
- Run **Forte → Run Decoder Self-Test**.
- Run **Forte → Report LLIL Coverage** when a Forte function exists.
- Search open issues for the mnemonic, p-code opcode, or failure message.

## Development setup

Forte's decoder tests do not require Binary Ninja:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
```

To test the integration, clone or symlink the repository into Binary Ninja's
user plugin directory and restart Binary Ninja.

## Good test fixtures

Please contribute the smallest byte sequence that demonstrates the behavior:

- include endianness and load address;
- include the expected disassembly and flow edges;
- include delay-slot bytes when relevant;
- use freely redistributable or synthetic bytes;
- do not commit vendor firmware, credentials, or `.bndb` files.

## Pull requests

1. Keep decoder behavior independent from Binary Ninja where practical.
2. Add or update tests for every semantic change.
3. Explain any LLIL approximation and its data-flow impact.
4. Run `pytest` and `ruff check .`.
5. Update `CHANGELOG.md` for user-visible changes.

Small, focused pull requests are easiest to review.
