# Move Capability Patterns

Notes on capability-based access control in Move (Sui and Aptos). Coming from an EVM background, Move's resource model is fundamentally different — you cannot call arbitrary functions on arbitrary contracts, and capabilities (special objects) gate privileged operations instead of `msg.sender` checks.

This repository documents patterns I found while reading open-source Move contracts, with a focus on what can go wrong.

## Contents

- [capability-basics.md](capability-basics.md) — what capabilities are and how they differ from EVM access control
- [common-mistakes.md](common-mistakes.md) — patterns that compile but create security holes
- [sui-specific.md](sui-specific.md) — Sui object model quirks that affect security

## Why Move

After spending a year on EVM auditing, I started looking at Move because:
1. More DeFi TVL is moving to Sui and Aptos
2. The security model is different enough that EVM audit intuitions do not transfer directly
3. The capability pattern is elegant but has its own failure modes that are under-documented

## Related

- [evm-audit-checklist](https://github.com/mehvetero/evm-audit-checklist) — EVM-focused checklist (started there, now expanding to Move)
- [defi-incident-notes](https://github.com/mehvetero/defi-incident-notes) — post-mortem analysis of real incidents







