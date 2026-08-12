# Sui-Specific Security Notes

## Object Ownership Model

Sui has four ownership types:

1. **Owned**: belongs to a specific address. Only that address can use it in a transaction.
2. **Shared**: accessible by any transaction. Requires consensus ordering.
3. **Immutable**: frozen forever. Anyone can read, nobody can modify.
4. **Wrapped**: stored inside another object. Accessibility depends on the parent.

Security implications:
- Owned objects enable parallel transaction execution (no consensus needed) — fast but means the owner is a single point of failure
- Shared objects go through consensus — slower but accessible by multiple parties
- Converting owned → shared is one-way and irreversible

## Programmable Transaction Blocks (PTBs)

PTBs allow composing multiple operations in a single transaction without deploying a contract:

```
1. split coins
2. call protocol A deposit
3. call protocol B swap
4. transfer result
```

Security implications:
- PTBs enable flash-loan-like composability WITHOUT a flash loan contract
- Any sequence of public function calls can be composed atomically
- Protocols cannot assume their functions are called in isolation
- `entry` functions cannot be composed in PTBs — use `entry` for operations that should not be part of a larger atomic sequence

## Clock and Randomness

- `Clock` is a shared object (`0x6`) updated by validators each checkpoint (~2-3 seconds)
- Not manipulable by users (unlike EVM `block.timestamp`)
- Randomness: `Random` object (`0x8`) provides on-chain randomness post-Sui v1.22
- Pre-1.22: no native randomness, protocols used commit-reveal or external oracles

## Type Confusion in Generic Functions

```move
public fun process<T: store>(item: T) {
    // This function accepts ANY type with store ability
    // If it does something security-sensitive, the type parameter
    // must be constrained or verified at runtime
}
```

An attacker can pass a custom type that satisfies the ability constraints but has unexpected behavior. For example, a custom `Coin<FakeToken>` passed to a function expecting `Coin<USDC>` if the function only checks `Coin<T>` generically.

Defense: use witness pattern or verify the type via `type_name::get<T>()` at runtime.

## Module Initializer (`init`)

- Runs exactly once when the package is published
- Cannot be called again (not even by the package owner)
- Used to create admin capabilities, set initial state
- If the init function is buggy, there is no way to re-run it — the only option is to publish a new package

What to check:
- Does `init` create all necessary capabilities?
- Does it transfer them to the right address (not a hardcoded address that might be wrong)?
- Does it set all initial parameters (fees, thresholds, oracle addresses)?

## Cetus Protocol Exploit ($260M, May 2025)

The largest Sui DeFi exploit so far. Not a capability bug — it was a math/overflow issue in the concentrated liquidity pool:

- Attacker exploited a rounding error in the `checked_shlw` function (bit shift)
- The overflow caused the pool to return more tokens than the actual liquidity justified
- Drained across multiple pools in minutes

Lessons for Sui auditors:
1. Math libraries in Move need the same scrutiny as in Solidity — `u128`/`u256` overflow, rounding direction, edge cases at min/max values
2. The Sui type system prevents reentrancy but does NOT prevent logic bugs
3. "Safe by construction" (Move's marketing) means memory-safe, not logic-safe
4. Concentrated liquidity math is inherently complex — any protocol forking Cetus-style pools should get independent math review, not just a code audit

## Attribute Scope in Move — the `#[test_only]` Annotation Trap

Move attributes (`#[test_only]`, `#[test]`, `#[expected_failure]`) apply to **the next item only** — the next function, struct, use, or const. They do not scope to a block or a file.

This sounds simple, but it creates a class of bugs in any tool that parses Move source:

```move
module example::pool {
    #[test_only]
    use sui::test_scenario;      // ← attribute applies to this use

    public fun drain(pool: &mut Pool) {   // ← this is NOT test_only
        pool.balance = 0;
    }
}
```

A static analysis tool that tracks `#[test_only]` as a boolean flag — set when seen, cleared when a function is found — will skip `drain` because the flag was set by the `use` statement two lines above. The attribute consumed its target (`use sui::test_scenario`), but the flag persists.

This is not hypothetical. I found this exact bug in my own linter (move-test-gen MOV-001) during a security audit. The fix: clear the flag on **any** item keyword (`fun`, `use`, `struct`, `const`), not just `fun`.

The same trap applies to `#[test]`:

```move
#[test]
const SETUP_VALUE: u64 = 42;    // ← attribute consumed here

fun real_production_code() {     // ← this is NOT a test function
    // ...but a naive parser thinks it is
}
```

What makes this insidious: `#[test_only] use sui::test_scenario;` is one of the most common lines in a tested Move module. A linter that skips the first function after it is silently blind on a large fraction of real codebases.

Rule: when parsing Move attributes, consume the flag on the **next item of any kind**, not just the next function.

## Mistake #9 — Package Upgrade Without Retiring Old Entry Points

On Sui, upgrading a package does not disable the previous version. Both versions remain callable on the same shared objects. This is by design — it prevents breaking existing integrations. But it creates a hard requirement: every version must agree on where mutable state lives.

When an upgrade relocates token storage (e.g., from a struct field to a dynamic object field), both the old and new versions can still read and write the same accounting fields. If they write different values, the shared field becomes version-dependent — its meaning changes depending on which version touched it last.

Concrete example (BlueMove, July 2026):

```
// V1 swap — writes reserve from pool balance
let (bal_x, bal_y) = token_balances(pool);
update(bal_x, bal_y, pool);
// → reserve_x = pool.token_x.value()

// V-latest swap — writes reserve from escrow balance
let esc_x = balance::value(&escrow.token_x);
let esc_y = balance::value(&escrow.token_y);
update(esc_x, esc_y, pool);
// → reserve_x = escrow.token_x.value()
```

Both versions call `update()`, which writes `pool.reserve_x`. But `pool.token_x` and `escrow.token_x` are independent balances. If the escrow holds 350,000 SUI and `pool.token_x` holds 7,000 SUI, whichever version wrote last determines whether `reserve_x` is 350K or 7K. Every formula downstream — LP pricing, withdrawal calculation, K-invariant check — computes a correct answer to the wrong number.

The three conditions that produce this:

1. **Storage relocation**: the upgrade moves assets to a new location
2. **Shared accounting field**: both versions overwrite the same field with values from their respective stores
3. **Old version still callable**: V1 functions are not gated or disabled

The fix is architectural: if you relocate storage, the old version's write path to the shared field must be disabled. On Sui, this means either version-checking inside the shared functions, or migrating all state in a single atomic transaction before burning the UpgradeCap.

Making the package immutable (burning UpgradeCap) after introducing a storage split locks the vulnerability in permanently.
