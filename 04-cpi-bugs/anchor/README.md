# 04 - CPI & PDA Vulnerabilities (Anchor Programs)

See the main [README.md](../README.md) for detailed documentation.

## Quick Start

```bash
# Build programs
anchor build

# Run tests
anchor test
```

## Programs

| Program | Type | Description |
|---------|------|-------------|
| `01-unchecked-program-id-vulnerable` | Vulnerable | Accepts any program for CPI |
| `01-unchecked-program-id-fixed` | Fixed | Uses `Program<'info, System>` |
| `02-unchecked-pda-vulnerable` | Vulnerable | No PDA seed verification |
| `02-unchecked-pda-fixed` | Fixed | Uses `seeds = [...], bump` |
| `03-arbitrary-cpi-vulnerable` | Vulnerable | Signs user-supplied instruction |
| `03-arbitrary-cpi-fixed` | Fixed | Hardcoded CPI logic |

## Tests

- `tests/04-cpi-pda-vuln.ts` - Demonstrates all three exploits
- `tests/04-cpi-pda-fix.ts` - Verifies fixes prevent exploits
