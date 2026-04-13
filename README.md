# merkle-asm

A depth-20 SHA256 Merkle tree written entirely in raw sBPF assembly using the [blueshift sbpf toolkit](https://github.com/blueshift-gg/sbpf).

---

## Benchmarks

### Compute Units

| Instruction    | merkle-asm | Quasar | Pinocchio | Anchor |
|:---------------|:----------:|:------:|:---------:|:------:|
| **Initialize** | **712**    | 1,801  | 2,251     | 8,294  |
| **Insert**     | **3,699**  | 3,676  | 3,744     | 9,405  |
| **Verify**     | **3,192**  | 3,218  | 3,116     | 5,426  |

### Binary Size & Deployment Cost

| Metric          | merkle-asm    | Quasar   | Pinocchio | Anchor    |
|:----------------|:-------------:|:--------:|:---------:|:---------:|
| **Binary Size** | **5.8 KB**    | 28.4 KB  | 12.1 KB   | 145.2 KB  |
| **Deploy Rent** | **~0.04 SOL** | 0.20 SOL | 0.08 SOL  | 1.04 SOL  |


For other framework benchmarks credits [avhi](https://github.com/AvhiMaz/merkle)

---

## Setup

```bash
cargo install --git https://github.com/blueshift-gg/sbpf.git
```

## Usage

```bash
clone this repo

make build   # compile assembly to .so
make test    # run Mollusk tests
make cu      # print CU usage per instruction
```

---

## Instructions

All instructions take accounts `[authority (signer), merkle_tree (writable)]`.

| Disc   | Name         | Instruction Data                                         |
|--------|--------------|----------------------------------------------------------|
| `0x00` | `initialize` | `[bump: u8]`                                             |
| `0x01` | `insert`     | `[leaf: [u8; 32]]`                                       |
| `0x02` | `verify`     | `[leaf: [u8; 32], index: u32 le, proof: [[u8; 32]; 20]]` |

---

## Account State Layout

The `merkle_tree` account is allocated with 10240 bytes (Solana max). Only the first 712 bytes are used.

```
offset  size  field
------  ----  ----------------------------------------
0x00    32    authority        pubkey allowed to insert
0x20     1    depth            always 20
0x21     1    bump             PDA bump
0x22     2    _pad
0x24     4    next_index       next available leaf slot (u32 le)
0x28    32    current_root     current Merkle root
0x48   640    filled_subtrees  20 × 32 bytes, one per tree level
```

---

## Error Codes

| Code   | Meaning             |
|--------|---------------------|
| `0x01` | Not enough accounts |
| `0x03` | Already initialized |
| `0x04` | Invalid instruction |
| `0x06` | Wrong authority     |
| `0x07` | Tree full (2^20)    |
| `0x08` | Zero leaf           |
| `0x09` | Invalid proof       |

---

## Design

**Input parsing** — uses `get_account_data_ptr` / `get_account_key_ptr` helpers that dynamically walk the serialized input buffer, skipping duplicate accounts and advancing by `ACCOUNT_BASE_SIZE + actual_data_len`. This correctly handles accounts of any size rather than relying on fixed offsets.

**Hashing** — `sol_sha256` is called with a single 64-byte input slice `[left || right]` (both halves written to the stack) rather than a two element slices array.

**ZERO_HASHES** — the 21 precomputed SHA256 chain values are embedded directly in `.text` as `lddw` immediates dispatched via a `jeq` table.

**No CPI overhead** — initialization writes directly to account memory, skipping System Program calls entirely.

**Tree capacity** — 2^20 = 1,048,576 leaves.

## ZERO_HASHES

```
ZERO_HASHES[0]  = sha256([0u8; 32])
ZERO_HASHES[i]  = sha256(ZERO_HASHES[i-1] || ZERO_HASHES[i-1])
ZERO_HASHES[20] = initial root of an empty tree
```

---

## Project Structure

```
merkle-asm/
├── Makefile
├── deploy/
│   └── merkle-asm.so
└── src/
    ├── merkle-asm/
    │   └── merkle-asm.s    # core sBPF assembly
    └── lib.rs               # Mollusk test suite
```

---

> **Disclaimer:** Raw, unchecked assembly. Thoroughly tested against the SVM but production use requires a full audit.