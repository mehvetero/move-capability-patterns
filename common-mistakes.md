# Common Move Security Mistakes

## 1. Shared Capability

```move
// DANGEROUS: AdminCap as a shared object
public fun create_shared_admin(ctx: &mut TxContext) {
    let cap = AdminCap { id: object::new(ctx) };
    transfer::share_object(cap);  // anyone can now use this
}
```

Why it is wrong: shared objects are accessible by any transaction. A shared `AdminCap` means anyone can call admin functions. Capabilities should almost always be owned objects, transferred to a specific address.

Fix: Use `transfer::transfer(cap, tx_context::sender(ctx))` instead of `share_object`.

## 2. Missing Capability Check in Friend Functions

```move
// Module A
public(friend) fun dangerous_operation(vault: &mut Vault) {
    // no AdminCap parameter — friend modules can call without authorization
}

// Module B (friend of A)
public fun user_facing(vault: &mut Vault) {
    a::dangerous_operation(vault);  // bypasses capability check
}
```

Why it is wrong: `public(friend)` trusts ALL friend modules equally. If any friend module exposes the operation without its own capability check, the access control is bypassed.

Fix: Require the capability in the friend function too, or use a separate internal capability that friends must obtain.

## 3. Capability Stored in Shared Object

```move
struct Config has key {
    id: UID,
    admin_cap: AdminCap,  // wrapped inside a shared object
}
```

Why it is wrong: if `Config` is a shared object, anyone can access it in a transaction. Even though they cannot extract `AdminCap` (no public unwrap function), if any function takes `&Config` and internally uses `&self.admin_cap`, the caller effectively has admin access.

Fix: Store capabilities in owned objects, not shared ones. Or use a pattern where the capability reference is obtained through a function that requires additional authorization.

## 4. UpgradeCap with Compatible Policy

Sui package upgrades have three policies:
- `compatible`: can change function bodies (keeping same signatures)
- `additive`: can only add new functions/modules
- `immutable`: no changes possible

```move
// If UpgradeCap has policy=compatible, the holder can:
// - Change the implementation of any function
// - Add new functions
// - Essentially replace the entire contract logic
```

Risk: `compatible` policy with a single EOA holding UpgradeCap means one private key can silently change how the contract works. Users interact with the same package address but get different behavior after upgrade.

What to check:
- What is the upgrade policy? (check on-chain via `sui_getObject` on UpgradeCap)
- Who holds the UpgradeCap?
- Is there a timelock or multisig on upgrades?
- Are upgrade events monitored?

## 5. Hot Potato Without Proper Resolution

The hot potato pattern uses a struct without `drop` ability to force a specific function call sequence:

```move
struct Receipt {  // no drop, no store, no copy
    amount: u64,
}

public fun borrow(vault: &mut Vault, amount: u64): (Coin<SUI>, Receipt) {
    let coin = vault.withdraw(amount);
    (coin, Receipt { amount })
}

public fun repay(vault: &mut Vault, coin: Coin<SUI>, receipt: Receipt) {
    let Receipt { amount } = receipt;  // destructure to consume
    assert!(coin::value(&coin) >= amount, EInsufficientRepayment);
    vault.deposit(coin);
}
```

The pattern is safe because `Receipt` cannot be dropped — the transaction MUST call `repay` to consume it. But mistakes happen:

- Adding `drop` ability to the receipt type (defeats the purpose)
- Providing an alternative destructor that does not enforce repayment
- Wrapping the receipt in another object that has `drop`

## 6. Oracle Price Update Without Staleness Check

```move
public fun update_price(feeder_cap: &PriceFeederCap, oracle: &mut Oracle, price: u64) {
    oracle.price = price;
    oracle.last_updated = clock::timestamp_ms(clock);
}

public fun get_price(oracle: &Oracle): u64 {
    oracle.price  // no staleness check
}
```

Any consumer of `get_price` trusts that the price is recent. If the oracle feeder stops updating (crash, key loss, network issue), the stale price persists indefinitely.

Fix:
```move
public fun get_price(oracle: &Oracle, clock: &Clock): u64 {
    let now = clock::timestamp_ms(clock);
    assert!(now - oracle.last_updated < MAX_STALENESS_MS, EStalePrice);
    oracle.price
}
```

## 7. Single-Key Admin on High-TVL Protocol

Not a code bug — an operational risk. If the protocol has >$10M TVL and the admin is a single EOA:
- Private key compromise = total loss
- Key loss = permanent lock (no recovery)
- No accountability (one person can rug)

Pattern seen in multiple Sui protocols. The fix is straightforward:
- Multisig (2-of-3 minimum) for admin operations
- Timelock on upgrades and parameter changes
- Event emission for all admin actions (most Sui protocols miss this — MoveBit DIS-1 finding is common)

## 8. Authorization Check Without Assert (Typus Pattern)

The most dangerous variant of mistake #1 — the authorization function is called, the arguments are correct, the code reads like a proper check, but the result is silently discarded:

```move
// DANGEROUS: return value of contains() thrown away
public fun update_v2(
    oracle: &mut Oracle,
    update_authority: &UpdateAuthority,
    price: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    // "check authority"
    vector::contains(&update_authority.authority, &tx_context::sender(ctx));
    // ↑ returns bool, nobody reads it
    update_(oracle, price, clock, ctx);
}
```

Why it is dangerous: this is harder to spot than a missing check entirely. A reviewer sees `vector::contains`, sees the authority parameter, sees the comment — and moves on. The function name implies a check. The arguments are correct. The only thing missing is one keyword:

```move
// FIXED: assert the result
assert!(
    vector::contains(&update_authority.authority, &tx_context::sender(ctx)),
    E_UNAUTHORIZED
);
```

Real-world impact: Typus Finance lost $3.44M in October 2025 to exactly this pattern. The oracle module had been live for eleven months. MoveBit audited the protocol — the oracle was excluded from scope.

Why Move does not catch this: `vector::contains()` returns `bool`. `bool` has the `drop` ability in Move, so discarding it is a valid operation. The compiler emits no warning. Rust has `#[must_use]` for this — Move does not have an equivalent annotation.

Three different objects, three authorization patterns in the same codebase:

| Object | Created with | Who can use | Auth mechanism |
|--------|-------------|-------------|----------------|
| `ManagerCap` | `transfer::transfer` (owned) | Only the holder | Ownership — type system enforces |
| `UpdateCap` (post-fix) | `transfer::share_object` (shared) | Anyone who passes `assert!` | Runtime check — developer must remember |
| `UpdateAuthority` (vulnerable) | `transfer::share_object` (shared) | Anyone at all | None — check result discarded |

The owned pattern (`ManagerCap`) cannot fail this way — you either have the object or you do not. The shared-with-assert pattern (`UpdateCap`) works but depends on the developer writing the assert. The shared-without-assert pattern (`UpdateAuthority`) is the $3.44M bug.

When to pick shared over owned: multiple addresses need concurrent access (e.g., automated crankers updating an oracle from different wallets). In that case, the `assert!` is the entire access control — there is no structural backup. Test it, lint for it, and treat its absence as a critical finding.
