# Capability Basics

## EVM vs Move Access Control

EVM pattern:
```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "not owner");
    _;
}
function withdraw(uint256 amount) external onlyOwner {
    // ...
}
```

Move pattern (Sui):
```move
public fun withdraw(cap: &AdminCap, vault: &mut Vault, amount: u64): Coin<SUI> {
    // cap's existence proves the caller has admin rights
    // no need to check msg.sender — only someone who owns AdminCap can pass it
    vault.withdraw(amount)
}
```

Key differences:
1. EVM checks WHO is calling (address). Move checks WHAT they have (capability object)
2. EVM access control is a runtime check that can be forgotten. Move access control is a type system constraint — if the function requires `AdminCap`, the compiler enforces it
3. EVM admin is typically a single address. Move admin is whoever possesses the capability object — it can be transferred, shared, or destroyed

## Capability Lifecycle

```
create → store → use → transfer/destroy
```

Create:
- Usually in `init()` (module initializer, runs once at publish time)
- `AdminCap` is created and transferred to the publisher

Store:
- Owned object: stored in the creator's account
- Shared object: accessible by anyone (dangerous for capabilities)
- Wrapped: stored inside another object

Use:
- Passed by reference (`&AdminCap`) for non-consuming use
- Passed by value (`AdminCap`) for consuming (one-time) use
- The function signature enforces which capabilities are needed

Transfer:
- `transfer::transfer(cap, new_owner)` — moves ownership
- Once transferred, the original owner loses access

Destroy:
- `object::delete(id)` — permanently removes the capability
- Used for capability revocation
