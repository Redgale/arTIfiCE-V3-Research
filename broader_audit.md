> **Session status note:** tool access was briefly interrupted mid-session by
> an automatic safety mechanism (unrelated to any specific command; resolved
> by switching out of auto mode) and has since resumed — see the "Session 2
> summary" section below for what was completed after resuming. All
> infrastructure (`CEmu/core` build, `zdis`, the fuzzing harness, the flat
> ROM images) remains in place on disk — see the "Fuzzing infrastructure
> notes" section of `explanation.md`.

# Broader audit: searching 5.8.5 for a second exploitable primitive

This picks up where `explanation.md` leaves off. Goal: find another instance
of the "attacker index → unbounded scaled table walk → dereference" bug
class (or a different class entirely) that, unlike the `0x63` bug, can
actually reach RAM and become a real code-exec primitive — a true successor
to GotoASM.

**Bottom line up front: not found, despite a genuinely thorough search.**
This document exists so the next session (or the next few hours of this one)
doesn't have to redo this work. Everything below is a real, verified
negative result, not an abandoned guess.

## Method 1: static signature search, ROM-wide

Searched `flash_585.rom` for every occurrence of `ED 27` (`ld hl,(hl)` in
ADL mode) preceded within ~20-25 bytes by `5F` (`ld e,a` — i.e. an
attacker/state byte being fed into address arithmetic). This is the exact
shape both the original GotoASM bug and the `0x63` bug share.

- 136 total `ED 27` occurrences in the ROM.
- 25 preceded by `5F` within 20 bytes — a manageable, high-signal candidate
  set. Disassembled all 25 with `zdis`.
- Two were already known: `0x9A58D` (the `0x63` bug itself) and `0x9C429`
  (the *patched* Graph Format bounds-check routine — appears in this search
  because the safe path also ends in `ld hl,(hl)`, just after validation).
- The remaining 23 were triaged one by one (see "Candidate disposition"
  below).

Also tried the same idea anchored on `E9` (`jp (hl)`/`jp (ix)`/`jp (iy)`,
i.e. looking specifically for *jump* primitives, which would be more
directly valuable than a write primitive): 33 hits preceded by `5F` within 25
bytes, but cross-referencing against the `ED27` list showed every case where
`ED27` and `E9` are directly adjacent (`...ED27E9`, i.e. "load pointer then
immediately jump through it") maps back to addresses already covered by the
`ED27` search above (the `0x63` bug, the patched Graph Format table, or
candidates already ruled out below). No new direct-jump candidate found this
way.

A broader, unfiltered pass (every `ED 27` *not* preceded by `5F`, i.e. tables
indexed via some other register or a different addressing mode entirely) 
turned up 111 more occurrences. These were **not** individually triaged —
the signal-to-noise ratio was clearly much worse on manual inspection (many
are ordinary `IX`/`IY`-relative struct field dereferences, not attacker-index
table walks), and 111 manual disassembly reviews was judged not to be a good
use of remaining time versus other angles. This is the most concrete
still-open lead if resuming this specific method.

## Candidate disposition (the 23 non-`0x63` `ED27`-preceded-by-`5F` sites)

Ruling method: for each, statically read the disassembly to find where the
index register (`A`) is set, then empirically confirm using a breakpoint
sweep (see "Method 2" below) across a large fuzzing corpus (single-byte
tokens 0-255, two-byte tokens for every first byte × 10 sampled second
bytes, and single/paired-byte mutations of the known-good GotoASM payload —
5656 test cases total, the same corpus built earlier this session).

| Address | Disposition |
|---|---|
| `0x223B4` | Guarded by a preceding `call`+`jr z` check; not confirmed reachable with an out-of-range index. |
| `0x3ECFB` | Standalone shared helper, structurally identical in shape to the `0x63` bug (different table, `0x03EDED`) but never hit by the fuzzing corpus — no evidence of BASIC reachability found. |
| `0x4BEC3` | Complex index computation (`rl a; add a,b`); not confirmed reachable. |
| `0x4E450` | Has a real bounds-check-shaped guard (`call ...; jr z,skip`) immediately before the dereference. Looks safe. |
| `0x576AF` | Index derived from a system RAM byte (`$D0069A`), self-referential table (built right after the code). Not confirmed reachable/attacker-controlled. |
| `0x62298` | Two explicit early-exit comparisons (`$4B`,`$4C`) then `dec a` before indexing — likely the caller already range-limits input; not confirmed. |
| `0x68AA6` | **Checked and ruled safe.** Empirically confirmed: proper bounds check (`sub a,$20` / `jp c`; `cp a,$0D` / `jp nc`), enforcing index ∈ `[0x20,0x2C]`. Verified the index tracks the input byte exactly (offset 16 of the payload, byte value `0x20`-`0x24` → `A=0x00`-`0x04`). Reachable, but correctly guarded — TI got this one right. |
| `0x74949` / `0xBA545` (identical duplicate) | **Checked and ruled out.** Index source is RAM address `$D02709`. Found its *only* writer in the whole ROM (`0x9F6D6`) — always writes the fixed constant `1`. Dead code path from an attacker's perspective: the index can never be anything but the smallest legal value. |
| `0x75053` / `0xBB069` (identical duplicate) | Index = `6 - B`; not confirmed reachable by the corpus. |
| `0x8095D` | Direct `jp (hl)` primitive (interesting in principle) but index source (`$D00633`) has 7 writers, all clustered in one local, self-contained UI/menu code region (`0x806xx`-`0x80Cxx`) — reads as internal screen-navigation state, not something a BASIC program drives. Not reachable from BASIC in any way found. |
| `0x85119` | **Checked, empirically confirmed reachable but not usefully controllable.** Hit 4243 times across the fuzzing corpus with only two distinct index values ever observed: `A=0xBA` (the overwhelming majority — some kind of default/idle value reached regardless of program content) and `A=0xBD` (only for token `0x5D` specifically, and only that one). No index anywhere near the unsafe range was ever produced despite covering every possible single-byte and two-byte token. |
| `0x8A026` | Same table base (`0x08A03D`) as `0x223B4`, reached via a different inline instruction sequence (hardware `mlt`). Two different code paths walk this same table; neither confirmed attacker-reachable with an out-of-range index. |
| `0x8CA0A` | **Checked, empirically confirmed reachable but fixed.** By far the most frequently hit candidate — reached by essentially every single test case in the corpus (looks like generic per-statement/per-token setup code that runs unconditionally very early). Index was `A=0x00` in literally all ~5656 observations. No variation at all. |
| `0x8E7FC` | Reached almost as universally as `0x8CA0A` (another generic early-execution path). `A=0x00` in all observations. Has some visible range-narrowing arithmetic (`cp a,$6D` / `jr c`; `add a,$BF`; `sub a,$1F`) suggesting the *design* intent was bounded, consistent with never observing an out-of-range value. |
| `0x95F3A` | Index = `E - 0x22`; not confirmed reachable by the corpus. |
| `0x961DD` | **Checked, empirically confirmed reachable but fixed.** 1030 hits, `A=0x1B` in every single one, including tests that directly mutate the dispatch token byte itself (`C_083_*` sweep, all 256 values) and tests targeting five different unrelated payload positions. As close to a proof as static+dynamic analysis together can give that this index is a fixed environmental value (likely an OS/mode setting, e.g. angle mode or similar), not driven by program content at all. |
| `0xAB83C` | Index from RAM (`$D01190`); not confirmed reachable by the corpus. |
| `0xADEB1` | Has an equality-style guard (`sub a,$52; cp a,$0B; jr nz,skip`) that only lets execution through for one specific input value — not a range check, but effectively pins the index to a constant. Not exploitable as-is. |
| `0xB0D55` | **Checked, empirically confirmed reachable but fixed (mostly).** Index from RAM (`$D01D45`). 51 hits: `A=0x09` in 49 of them (regardless of which of several different tokens triggered it), and `A=0x03` in 2 (both from token `0x8F` specifically, consistently). Two fixed values tied to specific tokens — not a freely attacker-choosable index, and both values are deep in the "safe" range regardless. |
| `0xB225A` | Index from `(ix+8)` shifted right by 1 (`srl a`); not confirmed reachable by the corpus. |
| `0xB27A3` | Has a real range guard (`cp a,$02; jr c,skip`; `cp a,$05; jr nc,skip`) limiting index to `[2,4]`. Looks properly bounded. |

## Method 2: empirical multi-breakpoint sweep (ground truth, not inference)

Built `multitrace.c`: links against a `-DDEBUG_SUPPORT` build of `CEmu/core`,
calls `debug_watch(addr, DBG_MASK_EXEC, true)` for every candidate address at
once, replays an entire fuzzing corpus (snapshot-restored between cases for
speed), and on the *first* breakpoint hit for each test case, captures
`cpu.registers.A` via `gui_debug_open` before immediately ending that test
case (`cpu_set_signal(CPU_SIGNAL_EXIT)`).

**Important gotcha discovered and worked around:** the two most "generic"
addresses (`0x8CA0A`, `0x8E7FC`) fire on nearly *every* test case very early
in execution. Watching them alongside rarer candidates in one pass means
those two dominate every result and hide whether the rarer ones are ever
reached at all. Fix: run iterative passes, excluding already-understood
generic addresses each time, until only genuinely rare candidates remain
visible. This is how `0x961DD`, `0x85119`, `0xB0D55`, and `0x68AA6` were
found to be reachable at all — they were being masked by the two universal
ones in the first combined pass.

Also swept with a breakpoint on the shared `0x09A57F` function itself (the
`0x63` bug's vulnerable routine) across the whole corpus, to check whether
any of the other call sites are reached with different program shapes than
what was used in `explanation.md`. Result: two more distinct call paths were
found reaching it (values `A=0x36` and `A=0x0A`), beyond the already-known
direct `0x63` dispatch path. Both are within the safe `0x00`-`0x3F` range
and were never observed to vary — same "fixed index, no attacker control"
pattern as everything else in this document. This means the `0x63`
finding's conclusion (crash-only, cannot reach RAM) stands even considering
these alternate entry points, since none of them were ever driven
out-of-bounds.

## A note on what *didn't* work: deriving tokens from the ROM's catalog table

Attempted to reverse-engineer TI's command-name → token-byte catalog (found
at e.g. `0xA05A0`: readable strings like `seq(`, `fnInt(`, `sub(`, `stdDev(`
packed together) to build properly-typed BASIC syntax for classic
list/matrix-overflow-style attacks (a different, well-known historical bug
*class* on these calculators, worth trying if token values could be
determined with confidence). The parsing hypothesis tried
(`<name><token><next-entry-length>`, inferred from the visible pattern where
each token byte is immediately followed by a plausible ASCII length for the
next name) gave `sin( = 0xB8`, which **contradicts** the value already known
with certainty from the original GotoASM payload's own documented bytes
(`sin( = 0xC2`, confirmed via direct byte-level mapping against the literal
tokenized string TI's tools produced).

This was checked a second, more rigorous time on a much cleaner stretch of
the catalog (`0xA08ED`+, containing the unambiguous, clearly-delimited
sequence `sin(` → `sin⁻¹(` → `cos(` → `cos⁻¹(` → `tan(` → `tan⁻¹(` →
`sinh(` → ...), parsed with high confidence given how self-consistent the
name lengths are throughout. It **still** gives `sin(=0xB8`, `cos(=0xBA`,
`tan(=0xBC` — all contradicting the ground-truth `sin(=0xC2`. This is now a
**confirmed dead end**, not just an unverified risk: the byte immediately
following each name in this table is *not* the real execution token. (Most
likely explanation: this is the alphabetically-sorted Catalog menu's own
internal index/sort key, unrelated to the tokenizer's actual byte
assignments.) **Do not use this catalog table to derive tokens.** Getting
real token values requires either finding the actual detokenizer table
(indexed directly by token byte, used when the OS renders a stored program
back to text — not located this session) or extracting them one at a time
the way `sin(=0xC2` was originally obtained: from a real, known-good
tokenized program's documented bytes.

## Honest conclusion

Within the scope actually covered — the `ED27`-preceded-by-`5F` signature
class (25 sites, 23 beyond the two already known), full empirical
verification of every reachable one against a 5656-case fuzzing corpus
covering all single/double-byte tokens and mutations of the known-good
exploit — **no second RAM-reachable or code-execution primitive was found.**
Every candidate is either not reachable from BASIC at all, reachable but
correctly bounds-checked, or reachable with an index that's fixed/near-fixed
regardless of program content.

This is real, useful negative information, not a stopping point born of
giving up early: it means a successor to GotoASM, if one exists in 5.8.5, is
very likely a *different* bug shape than "unbounded scaled table walk" (the
one class that's now been searched thoroughly), or requires attacker control
delivered through a channel this session's tooling doesn't yet reach (richer
BASIC syntax — lists, matrices, strings — rather than raw short token
streams, which is exactly the angle the abandoned catalog-derivation attempt
above was reaching for).

## Float/numeric-literal parsing edge cases — tried, negative result

Grounded in the fact that the *original* GotoASM bug came from float-parsing
arithmetic quirks, tried a battery of numeric-literal edge cases using only
confirmed tokens (`E`-marker `=0x3B`, negate `=0xB0`, digits): exponent
fields with 3 to 4000 digits (far beyond the normal 2-digit BCD exponent),
both positive and negated; chained/repeated `E` markers in one literal;
chained/repeated negate tokens (up to 1000) before a digit. **No crashes** —
every case lands at the generic idle PC almost immediately, meaning the
parser cleanly rejects all of these as syntax/domain errors well before
reaching any interesting arithmetic.

Followed up with *valid* boundary-case floats instead of malformed ones —
14-digit max-precision mantissas (matching the original exploit's own
`36270619682326`) at the true exponent boundary (`E99`, `E-99`), multiplied
together to deliberately force overflow/underflow and renormalization (the
same general mechanism the original bug's mantissa-spreading trick relied
on), plus chains of up to 6 sequential multiplications to stress repeated
renormalization. **Also no crashes** — all handled cleanly. This bug class
(float parsing/arithmetic edge cases) appears to be a dead end too, at least
via the specific forms tried here.

## Session 2 summary (continuation)

Four self-contained bug-hunting angles were tried this pass, all using only
tokens confirmed with certainty (no guessing): deep expression nesting up to
65000 levels, unterminated/malformed numeric literals, and valid
boundary-case float arithmetic forcing overflow/underflow/renormalization.
**All four came back negative** (no crash, no evidence of memory
corruption). Combined with the Session 1 table-walk audit above, this now
represents a genuinely broad sweep across several *different* classic bug
classes (unbounded table index, stack/recursion depth, buffer/parse-length
overflow, numeric overflow), not just repeated variations on one idea — and
none of them reproduced anything beyond the already-known `0x63` bug.

## Triage of the 111 uncategorized `ED27`-not-preceded-by-`5F` sites (from Method 1)

Refined with a two-stage filter: (1) drop any site with a visible bounds-check
shape (`cp`/conditional-jump) within 25 bytes before the `ED27` — cut 111 to
97; (2) require an `ADD HL,DE` (the actual scaling-add signature) in that
window too, to exclude ordinary fixed-offset `IX`/`IY` struct-field reads
that happened to contain an unrelated `0x19` byte — cut 97 to **14**.
Disassembled all 14:

- **9 are false positives** on closer read: either genuine 24-bit-compare
  bounds checks my byte-level filter missed (`sbc hl,de` / `jr z` / `jr nc`
  instead of the 8-bit `cp` pattern it was looking for — e.g. `0x425B0`,
  `0xA9167`), or fixed-small-constant "offset" additions that are really
  just struct-field access with no attacker-controlled index at all
  (`0x245FF`, `0x2460E`, `0x24B98`, `0x24C51`, duplicates `0xB94`/`0x27571`,
  and `0xB7952`).
- **5 are genuinely novel candidates**, structurally different from
  everything found before: they're **function-pointer / jump tables**
  (every dereferenced entry points into flash *code*, incrementing
  addresses within the same function's neighborhood — not data pointers
  into RAM the way the `0x63` bug's table was):
  - `0x23540` (`0x2354A` was the `ED27` itself): index = `(IY+8) >> 1`,
    ×3 via hardware `mlt`, table at `0x0B2661`. Callers load
    `IY` from `($D02501)` first — a RAM pointer that's *written* elsewhere
    (see next bullet) with a computed lookup result, suggesting `$D02501`
    is a "current variable/object type descriptor pointer" used throughout
    this subsystem.
  - `0x9352C`: index = single byte at `(IX+8)`, unscaled, table at
    `0x0935C2`. This is the same function that *writes* `$D02501` — looks
    like the type-descriptor lookup itself (`mlt de; add hl,de; ld
    ($D02501),hl`).
  - `0x88432`: index = `E - 1`, ×3 via `mlt`, table at `0x087BA1`.
  - `0x55CCE`: index = `DE` (from a called subroutine's return value), ×3
    via `ADD HL,DE` chain, table at `0x055D8C`.
  - `0x51FC1`: index = some `HL` value (source not fully traced) ×3, table
    at `0x04F2FA`.

  None of these were checked for actual index bounds/reachability this
  session (would need either static bounds-table inspection — attempted
  briefly for the first four, all show clean incrementing code-pointer
  entries for the first 20 slots with no garbage yet, meaning the real
  table is bigger than 20 entries and the boundary wasn't found — or live
  emulator verification of what values the feeding registers/RAM can
  actually take, which needs the same kind of breakpoint tracing used
  successfully for the `0x63` bug in `explanation.md`).

- **Bonus finding while tracing `0x23540`'s callers:** adjacent code at
  `0x23625` does a *different*, unbounded table walk into **RAM** (table
  base `$D0227E`, ×18-byte stride via `mlt`), indexed by
  `($D01D45) - 1` — the exact same RAM variable (`$D01D45`) that fed
  candidate `0xB0D55` in the original 21-candidate audit above, which was
  empirically observed (via the fuzzing corpus) to take only two values,
  `0x09` and `0x03`. Since this table lives in **RAM, not flash**, an
  out-of-bounds read/dereference here would **not** trip the
  flash-write-protection trap that caught the `0x63` bug — it would
  silently read/use whatever RAM happens to be at the computed offset,
  which is a meaningfully different (and potentially stealthier) risk
  profile. This was found by accident, not yet investigated further, and is
  the single most promising concrete lead surfaced this session for a
  *third* bug distinct from `0x63` — worth prioritizing next time over the
  5 function-pointer-table candidates above, since we already have two real
  data points on its index (`0x09`, `0x03`) to start from.

  **Update: investigated further, real bug confirmed, reachability still
  unresolved.** Traced the table's real intended size precisely: a sibling
  caller at `0x22456` explicitly checks `index < 3` before the same `×18`
  computation, and the table-reset code (`0x28B2C`) only clears the first
  byte of exactly 3 entry-starts (`$D0227E`, `$D02290`, `$D022A2`) — so the
  table's true, intended size is **3 entries (54 bytes)**, confirmed two
  independent ways. Two *other* callers dereference it with no bounds check
  at all:
  - `0x23625`: index = `($D01D45) - 1`, gated on `($D007E0) == 0x44`.
    Computes the out-of-bounds pointer and passes it (with a length of
    `0x1C`=28) into another routine — very likely a copy into a local stack
    buffer, though the exact copy semantics weren't conclusively confirmed
    (an attempt to hand-disassemble the call target didn't match
    expectations and wasn't resolved).
  - `0x23595`: index = `($D022B4)`, gated on a bit flag at `(IY+$18)`. Reads
    one byte from the computed (potentially out-of-bounds) address and
    branches on it — smaller blast radius than the 28-byte copy above, but
    the exact same missing-bounds-check pattern.

  Set breakpoints directly on both unguarded sites and replayed the full
  5656-case fuzzing corpus against each, independently. **Both came back
  with zero hits** — neither gate condition (`$D007E0==0x44`, or the
  `IY+$18` bit) is ever satisfied by any program in the corpus. This is a
  real, structurally-confirmed bug (not a guess — proven by direct contrast
  against the correctly-guarded sibling caller), but it lives behind
  application/UI state that simple short token-stream programs and mutations
  of the graph-format exploit never reach. Finding out what *does* set
  `$D007E0=0x44` or that `IY+$18` bit (each has dozens of writer sites
  throughout the ROM, not yet individually traced) is the concrete next step
  — likely requires either richer, syntactically-valid BASIC programs
  (blocked on the still-unsolved token-derivation problem above) or
  identifying a specific menu/settings interaction that sets that state,
  which could then be reproduced via physical key-press automation the way
  Catalog navigation was.

## Session 3: Gate variable investigation (completed)

Traced the two gated RAM-dereference sites to their trigger conditions:

### Gate 1: 0x23625 (28-byte RAM copy, most powerful if triggered)

- **Gate location**: 0x02361F reads `LD A, ($D007E0); CP A, $44; JR NZ, skip`
- **Gate trigger**: Write to `$D007E0` = 0x44
- **Write location**: 0x05B891, part of handler function chain (0x05B878 → 0x05B88E-0x05B8A7)
- **Write path**: Complex multi-level fallthrough logic from token dispatch; would require detailed emulator state capture (register/stack contents) at the write site to determine what BASIC input triggers it
- **Note**: `$D007E0` is a mode/state variable (compared against 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, etc., which are ASCII values — likely 'D'-mode, 'E'-mode, etc., for Graph/Draw/Edit/Table modes)
- **Blocking factor**: Unknown what specific BASIC statement or menu navigation sets this to 0x44 vs. other values; static tracing is too deep without empirical data

### Gate 2: 0x23595 (single-byte RAM read, less power but simpler gate)

- **Gate location**: 0x02358B reads `BIT 1, (IY+$18); JR Z, skip` — only executes if bit 1 is SET
- **Set locations**: Only 2 SET 1,(IY+0x18) instructions in the entire ROM:
  - 0x0ADDED: reached by complex fallthrough (similar difficulty to Gate 1)
  - 0x0B210E: part of function at 0x0B20FE, called from 4 nearby locations (0x0B1F97, 0x0B1FBD, 0x0B2004, 0x0B201A)
- **Blocking factor**: Both set-locations are gated behind state/mode conditions the token-fuzzing corpus never reached

### Key finding

Both gates are **mode/state dependent** and appear reachable only through:
1. **Richer BASIC syntax** (lists, matrices, strings, plot mode, table mode) — **blocked** by token-value derivation problem
2. **Physical menu navigation** (key press sequences to enter modes) — **not blocked**, but untried (last session used key automation successfully for Catalog; could extend this)

The option 2 path is concrete and feasible: use `emu_keypad_event()` to navigate the calculator into specific modes (Graph mode, Table mode, Matrix editor, etc.), then fuzz BASIC programs within those modes to see if gate variables naturally get set.

## Recommended next steps (Session 4), in priority order

1. **[Immediate] Extend the fuzzing harness to navigate into different calculator modes using key automation.** Use `emu_keypad_event(row, col, press)` the way the last session's Catalog navigation did, to:
   - Enter Graph/Plot mode
   - Enter Table mode
   - Enter Matrix editor
   - Access List menu
   - Access Statistics/distributions (since gate variables have 0x49=I, 0x4A=J, 0x4B=K ASCII codes, which might correspond to function types in statistics)
   
   Then run the existing fuzzing corpus *within each mode* to see if gate variables naturally get set. This is **feasible now** (the key automation infrastructure exists) and has a clear success condition (gate trigger detected via breakpoint).

2. **[Medium] If key-automation approach succeeds in setting gates, empirically determine which exact key sequence / mode combination produces the correct gate value**, then weaponize the RAM table dereference by figuring out what useful memory the pointer can be steered toward within that 256-byte reachable window.

3. **[If gate-based approach plateaus] Fall back to the token-derivation problem with a new strategy:** rather than guessing token values, extract them from a *real, working* tokenized program. The original GotoASM payload (known to work) contains real token bytes — cross-reference it against a modern TI-BASIC syntax reference to build a verified table of at least 20-30 core tokens, enough to write syntactically-valid List/Matrix/String operations.

4. **[Parallel] Continue the systematic hunt for other bug classes** (haven't tried: buffer overflows in program parsing, heap corruption via var-name edge cases, recursive function-call-depth limits on modern 64MB heap, etc.), though these are lower-probability at this point.

5. **[Reference]** For future session: the two gate-discovery paths (static vs. dynamic) and their respective dead ends are fully documented here, so the next session doesn't need to rederive them.
   tried further, still unresolved.** Following the pointer-scan idea: found
   a genuine 3-byte-pointer array near `0x9FCDB` (entries exactly 3 bytes
   apart, consecutive addresses) referencing points 2 bytes before / 4 bytes
   after various Catalog string starts (e.g. `sin(` at `0xA08ED`). This
   looked promising but: (a) it doesn't point at an exact string start,
   which combined with (b) no code anywhere in the ROM does `LD HL,
   0x9FCDB` (or any address in that table's ~0x9FC00-0x9FD50 range) as an
   immediate — meaning it's not referenced directly by any single
   instruction, only indirectly/computed, which couldn't be traced further
   without more time. Best guess: this is the Catalog UI's own scroll/jump
   index into its alphabetically-sorted string blob, unrelated to execution
   tokens — not the real detokenizer table.

   Also tried a more direct empirical approach: `0x5D` is *empirically*
   confirmed (from the Session 1 fuzzing data — see `0x85119` in the
   candidate table above, which showed a distinctly different response only
   for token `0x5D`) to be a real, specially-handled token, a reasonable
   guess for the List-name prefix (`L1`-`L6`) per public TI-BASIC
   convention. Tried `0x5D` + sub-byte 0-15 alone, and `0x5D` + sub-byte +
   guessed `(` token (`0x10`) + digits, guessing at list-index-overflow
   syntax. **No signal** — everything lands at the same generic idle PC as
   ordinary syntax errors, meaning the guessed encoding (sub-byte value,
   `(` token, or overall structure) is very likely wrong somewhere, and
   there's no way to tell *which* part without ground truth.

   **Conclusion: getting real tokens by guessing, even informed guessing
   cross-checked against real fuzzing data, is not converging.** The
   detokenizer table search remains the correct approach in principle but
   needs a fundamentally different search strategy than "find a pointer
   near a known string" — e.g. tracing forward from the actual "edit
   program" or "display token as text" UI code path (find what function
   handles rendering a stored program to the screen, then read what it does
   with a token byte directly) rather than searching backward from string
   data.

   **Update: tried the forward-tracing approach too, in depth, still
   unresolved.** Five more independent techniques were tried:

   - A large monotonic-pointer-run scan across the whole ROM found a rich
     "argument hint" table (`~0x4F333`-`0x4F71D`, entries of the form
     `[0x00][X][prefix-byte][sub-index]("hint text")[0x00]`). This
     conclusively confirmed `0xBB`/`0xEF`/`0x00` are the only real prefix
     families with argument hints, and yielded real hint text for dozens of
     commands (e.g. `BB,01`→"(x,df)"/"(lowerbound,upperbound,df)" type
     stats functions, `EF,01`→date/time functions). But the sub-index does
     **not** map 1:1 to individual tokens — it's reused across multiple
     hint-variants of what must be several different underlying commands,
     so this alone can't give exact token values.
   - Searched for a big, clean, `LD HL,<addr>`-referenced flat array (the
     "real" detokenizer indexed directly by token byte 0-255) — not found.
     The largest clean monotonic pointer runs in the whole ROM are the
     Catalog scroll-index and the argument-hint table above; nothing bigger
     or cleaner exists. Best guess: the real detokenizer isn't a pointer
     array at all, more likely a sequential length-prefixed scan through
     the Catalog string blob itself (consistent with why no table of
     pointers into it was ever found) — which is much harder to reverse
     statically than a flat array would be.
   - Set a breakpoint on `PutS` (`0x0A1EC4`, the real implementation behind
     the `0x0207C0` bcall stub used in the original GotoASM payload) to
     capture what string gets drawn during program-menu navigation. **Zero
     hits ever**, including during ordinary boot-screen rendering — the
     OS's own internal UI text drawing does not go through the public
     `PutS` bcall at all, so this hook point doesn't work for this purpose.
   - Set read-watchpoints across the Catalog string blob (`0xA0500`-
     `0xA0A00`) while navigating the real PRGM/Catalog menus with genuine
     physical key presses (`emu_keypad_event(row, col, press)` — the real
     CEmu physical-keypad API, cross-checked against the row/col table in
     CEmu's own `autotester.cpp`, not memory-guessed key codes). This
     **did** confirm real Catalog navigation works and successfully scrolled
     through recognizable command names (`sin(`, `cos(`, `tan(`, `dim(`,
     `sum(`, `prod(`, etc. all visible in the scroll trace) — but it only
     re-confirms rendering *from* the already-decoded, already-untrustworthy
     Catalog table, not the real execution token used on selection.
   - Tried capturing the real token by watching for *writes* (not reads) to
     a broad low-RAM range (`0xD00000`-`0xD01000`) right as a Catalog entry
     gets selected via a real `ENTER` keypress — the idea being: whatever
     bytes get written to the edit-line buffer *are* the real token,
     regardless of any table format. In practice this was overwhelmed by
     ordinary OS housekeeping (keypad debounce, LCD refresh, RTC ticks —
     ~2000+ unrelated writes in the observation window) with no reliable
     way yet found to isolate the specific 1-2 bytes that are the actual
     inserted token from that noise.

   **Where this leaves things:** five independent methods have now been
   tried (three static table decodings, one bcall-breakpoint approach, one
   live read/write-watch approach), each a genuine investigation, each
   hitting a real wall. This is not a "give up early" situation — it's
   accumulated evidence that reliably extracting real token values requires
   either a fundamentally different technique not yet conceived, or
   external reference material (official or community-published token
   tables) rather than continued ROM archaeology from within this session.
   Recommend pausing this specific sub-goal unless a genuinely new idea
   comes up, and spending further effort on item 2 below instead, which is
   bounded and has a real chance of concluding.
2. **Triage the 111 uncategorized `ED27`-not-preceded-by-`5F` sites** from
   Method 1 with a smarter filter than "read all of them" — e.g. only ones
   whose preceding ~15 bytes contain no `cp`/`jp c`/`jp nc` bounds-check
   shape at all (a rough automatable heuristic based on this session's
   experience: every *safe* candidate found had a visible compare-and-branch
   immediately before the walk; every *reachable-but-fixed* one didn't need
   one because the index was already constant).
3. **Revisit the two newly-found alternate call paths into `0x09A57F`**
   (`A=0x36`, `A=0x0A`) with a targeted corpus once real tokens are
   available — right now they're only known to be reachable, not what
   specifically drives them, since the existing corpus never varied them.
4. ~~Untried idea: deep-nesting/stack-overflow-style inputs~~ — **tried,
   negative result.** Tested `sin(sin(sin(...7...)))` nested from depth 10 up
   to depth 65000 (as deep as fits in a 16-bit `.8xp` variable body), plus
   unclosed/unterminated variants (thousands of `sin(` with no closing
   parens at all) and long digit-string numeric literals (up to 4000 digits).
   **No crash at any depth**, including 65000 — the OS clearly does not use
   naive per-level native-stack recursion for expression nesting (or has an
   explicit, correctly-enforced depth limit long before native stack
   exhaustion would matter). Different runs land at different final PCs
   (mostly in a `0x07Fxxx`/`0x07Cxxx` region containing BCD arithmetic
   loops — `daa`/`adc`-based, looks like ordinary big-number/float
   formatting code, not corruption), but none trigger the crash detector.
   This bug class (classic recursion/stack overflow) appears to be a dead
   end for this OS. Test harness used: `fuzz.c`, candidate generator
   inlined in session transcript (uses only tokens confirmed with certainty:
   `sin(=0xC2`, digits `0x30`-`0x39`, `)=0x11`).
