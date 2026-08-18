# Unpatched sibling of the GotoASM bug: token `0x63` unbounded table walk

## Status

Confirmed present and **unpatched** in OS 5.8.0, 5.8.3, and 5.8.5. Unlike the
Graph Format (`0x7E`) bug that GotoASM/arTIfiCE used, this one was **not**
touched by the 5.8.5 patch that added the `0x09C414` bounds-check helper (see
`../GotoAsm/explanation.md`). It is a distinct, independently-triggerable bug
in the shared handler for BASIC tokens `0x62`/`0x63`, in the same general
family as the original vulnerability: an attacker-influenced index is used to
walk a fixed-size lookup table with **no range check**, and the out-of-range
result is dereferenced.

This is a confirmed **crash-only primitive, and provably not escalatable to
arbitrary memory corruption in its simplest form** (bare 2-byte token
program). The full index → pointer mapping has been solved and empirically
verified (see "Full weaponization analysis" below): every reachable pointer
value necessarily falls inside flash address space, never RAM, so the
resulting write always trips the hardware's unprivileged-flash-write
protection and resets the device. It cannot be pointed at anything useful
using only this bug's own index byte. Escalating further would require
finding attacker control over the index through some other channel (see
"Open questions" at the end).

## How it was found

Built a headless CEmu automation harness (core library only, no Qt GUI) that:

1. Loads a flat 4MB ROM image (exported from CEmu's own "Export ROM Image"
   after installing a real OS `.8eu` via the GUI — the `.8eu` OS-upgrade
   container format is not flat/plain, see the note at the end of this repo's
   session history if reproducing).
2. Calls `emu_set_run_rate(1000)` **before** booting. This is required — at
   the default 10 MHz `CLOCK_RUN` rate, `emu_run()`'s USB/link scheduling
   never makes visible progress and file transfers hang forever. Slowing the
   run clock to 1000 Hz (mirroring what CEmu's own CI `autotester` tool does)
   fixes this completely; transfers then complete in a few call cycles just
   like on a real device.
3. Sends a candidate `.8xp` program via `emu_send_variables()`.
4. Injects keypresses (`CE_KEY_PRGM`, letter keys, `CE_KEY_ENTER`) via
   `sendKey()`/`sendLetterKeyPress()` from `core/extras.c` to launch the
   program named `A` from the program menu, exactly as a user would.
5. Watches `gui_console_printf`/`gui_console_err_printf` for CEmu's own
   hardware-accurate fault messages (`"Reset caused by..."`,
   `"Reset triggered"`, `"NMI reset caused by writing to flash..."`) as the
   crash signal — these correspond to real hardware protection traps, not an
   artifact of the emulator.

A snapshot (`emu_save(EMU_DATA_IMAGE, ...)`) taken right after boot is
restored before each test case so many candidates can be run per second
without a full re-boot each time.

Two fuzzing passes were run against 5.8.5:

- A brute-force sweep of every possible 2-byte program body (`<first-byte>
  <second-byte>`, sampled second bytes) plus every possible 1-byte program.
- Single- and paired-byte mutations of the *known-good* arTIfiCE v2.1 exploit
  bytes (guaranteed-valid input as a mutation seed, much higher yield than
  fully blind generation).

One crash was found and reproduced: `0x63 <index>` for most `index >= 0x40`.

## The bug

Token dispatch (`$D005F9` holds the parsed token byte) branches on value
`0x63` into a handler that eventually reaches, at a fixed offset from the
handler entry:

```
push af
ld   hl, TABLE_BASE     ; 0x09A5C4 in 5.8.5 (0x09A335 in 5.8.0, 0x09A593 in 5.8.3)
ld   e, a                ; a = attacker-influenced index byte (confirmed via breakpoint: A == the raw input byte, exactly)
add  a, a                 ; a = a*2   <-- 8-bit register, WRAPS mod 256
add  a, e                  ; a = a*3  <-- ALSO wraps mod 256 (this matters, see below)
ld   de, 0
ld   e, a
add  hl, de                 ; hl = TABLE_BASE + ((3*index) mod 256)   <-- NO BOUNDS CHECK
ld   hl, (hl)                 ; hl = 24-bit value read from table
pop  af
```

No comparison against a maximum index precedes this, unlike the patched
Graph Format table which now calls `0x09C414` to clamp `hl` into
`[table_start, table_end]` before dereferencing (see the other writeup).

**Important correction from an earlier draft of this document:** the `a*3`
computation happens entirely in the 8-bit `A` register, so it wraps modulo
256 — the byte offset used is `(3*index) mod 256`, *not* `3*index` as a true
integer. This was initially missed (a naive "table_base + 3*index" model was
assumed), which produced wrong predictions for which system address a given
index would hit. It was caught and corrected by setting a real breakpoint at
the function entry (`0x09A57F`) via CEmu's own debugger core
(`debug_watch(addr, DBG_MASK_EXEC, true)` + `gui_debug_open`) to directly
observe `A` at entry, and by re-deriving the formula from multiple
independently-confirmed `(index, resulting HL)` pairs. See "Full
weaponization analysis" below for the corrected, fully-verified model.

The loaded `hl` is later used as a pointer for a read-modify-write bit
operation (roughly "clear bit 6, then OR in some bits from another byte")
that ultimately executes `ld (hl), a` — a **write**, not a jump. When `hl` is
garbage (because the index walked off the end of the table into unrelated
flash bytes), this write lands wherever those garbage bytes point, including
straight into flash address space, which trips CEmu's/the hardware's
unprivileged-flash-write protection and forces a full device reset.

## Table bounds (5.8.5, confirmed empirically)

The real table has exactly **64 valid entries**, indices `0x00`-`0x3F`, each a
legitimate `0xD0xxxx`-range RAM pointer:

```
0x3f -> 0xD01F26   (last real entry)
0x40 -> 0x190502   (garbage, off the end)
0x41 -> 0x26251C   (garbage)
0x42 -> 0x0E2F2E   (garbage; this exact value is what crashed the repro below)
...
```

This exactly matches the empirical crash/OK boundary from fuzzing: indices
`0x00`-`0x41` mostly don't crash (either real entries, or garbage bytes that
happen to still decode to a harmless address), and crashes become frequent
and dense from `0x42` onward, continuing with occasional "safe" islands all
the way to `0xFF` (positions where the garbage 3-byte value from flash
happens to not point into a protected/flash region).

(Note: for indices up to ~`0x55`, `3*index` doesn't exceed 255, so the naive
"true integer" arithmetic above happens to still be correct — the `mod 256`
wraparound described later in "Full weaponization analysis" only starts
mattering for larger indices, which is why this table-bounds section and the
`0x42` repro below are accurate as-is, but predictions for indices like
`0x94`/`0x97` initially were not.)

## Reproduction

Minimal repro: a BASIC program whose entire token stream is just two bytes,
`0x63 0x42` (or almost any second byte `>= 0x40`), built into a `.8xp` with
`build8xp.py` from this repo and run from the program menu. No numeric/float
crafting of the kind GotoASM needs is required at all for this one — the
plain two-byte token stream is enough by itself.

Captured fault state for `0x63 0x42`:

```
PC = 0x09A5B1        (the "ld (hl),a" instruction inside the bit-flag helper)
HL = 0x0E2F2E        (exactly the out-of-bounds table[0x42] value, used as the write pointer)
A  = 0xBF
[CEmu] NMI reset caused by writing to flash at address 0xE2F2E from unprivileged code.
[CEmu] Reset caused by writing to bit 4 of port 0.
[CEmu] Reset triggered.
```

## Full weaponization analysis (solved)

Because `A` at function entry equals the raw input index byte exactly
(confirmed via a real CEmu-core breakpoint, not inference), and the offset
formula is `(3*index) mod 256`, and `gcd(3, 256) = 1`, sweeping `index` over
all 256 possible byte values visits **every possible byte offset 0-255
exactly once** — i.e. every single 3-byte-wide window (at *any* byte
alignment, not just multiples of 3) within the 256-byte flash range
`[TABLE_BASE, TABLE_BASE+255+2]` = `[0x09A5C4, 0x09A6C6]` is reachable as the
resulting "pointer," just by choosing the right index
(`index = (desired_offset * inverse_of_3_mod_256) mod 256`, where
`inverse_of_3_mod_256 = 171`).

This makes the reachable-pointer question fully decidable by static
inspection — no more fuzzing needed. A byte-by-byte scan of
`flash_585.rom[0x09A5C4 : 0x09A6C6]` for any 3-byte little-endian value
landing in the `0xD00000`-`0xD00800` system RAM range (where `OP1`-`OP6`,
the token fetch pointer `$D0231A` used by the original GotoASM exploit, and
other security-relevant globals live — see `../GotoAsm/explanation.md`)
comes back **empty**. Every reachable value is itself a flash address.

**Conclusion:** using only this bug's own index byte, the write can never be
aimed at RAM. It will always try to write into flash, which is always
intercepted by hardware protection, which is always a crash. This is a solid,
verified negative result — not a "didn't get around to it" gap — for this
specific bug in its simplest (bare 2-byte program) form.

Verification methodology (for reproducing or extending this analysis): built
a second driver (`traceA.c`) linking against a `-DDEBUG_SUPPORT` build of
`CEmu/core`, calling `debug_init()` once, then per test case
`debug_watch(0x09A57F, DBG_MASK_EXEC, true)` before sending/launching the
candidate program. `gui_debug_open(reason, data)` fires synchronously the
instant the breakpoint is hit, with `data == 0x09A57F`; reading
`cpu.registers.A` there gives the true index with zero ambiguity, then
`cpu_set_signal(CPU_SIGNAL_EXIT)` cleanly stops emulation for that test case.
This directly confirmed `A == index` for `0x00, 0x42, 0x63, 0xFF`, and the
corrected `(3*index) mod 256` formula was independently confirmed against
five different `(index, HL)` pairs collected from actual crash captures
(`0x42, 0x5F, 0x94, 0x97, 0xAA`), all matching exactly once the mod-256
wraparound was accounted for.

## Open questions / next steps

- Token `0x62` shares the same leading comparison (`cp a,$62` / `cp a,$63`
  against `$D005F9`) but takes a different call path afterward. A quick check
  (`0x62 0x60`) did **not** crash — `0x62` was not shown to reach this same
  vulnerable table, and no further investigation of its path was done.
- The shared vulnerable function at `0x09A57F` is called from **7 sites**
  across the ROM (found via a `CALL 0x09A57F` byte-signature search). Of
  these:
  - The `0x63` token dispatch site (this document's main subject) — fully
    analyzed, index is fully attacker-controlled, no RAM addresses reachable.
  - `0x447D8` — checked and **ruled out**: this call site passes a
    hardcoded constant (`ld a,$1A` / `ld a,$0A` nearby, not the fuzzed token
    byte) and is reached from unrelated internal OS bookkeeping code (looks
    like archive/link housekeeping, doing a `djnz` loop that sets bit 6
    across a run of bytes), not from BASIC token parsing at all. Not
    attacker-reachable.
  - `0x453D1` and the remaining 4 sites (`0x9A24C`, `0x9A6E4`, `0x9A946`,
    `0x9AEDD`, `0x9D6FA`) — **not yet checked**. Given `0x447D8` turned out
    to be a dead end, these are lower-confidence leads than originally
    thought, but still the most concrete remaining next step for this bug
    class.
- No investigation yet into whether the *other* small table (`TABLE2` at
  `0x09A684` in 5.8.5, indexed the same unbounded way, feeding the `ld
  (de),a` OR-in value rather than the pointer) has its own exploitable
  behavior independent of `TABLE1`.

## Fuzzing infrastructure notes (for continuing this work)

- Core library: build `CEmu/core` with `make` (produces `libcemucore.a`).
  Link a small driver against it with `-lcemucore`; no Qt/GUI dependencies
  needed for headless automation.
- **Must** call `emu_set_run_rate(1000)` before/shortly after `emu_load` or
  file transfers hang indefinitely — this was the key blocker solved during
  this investigation.
- Crash detection: override `gui_console_printf`/`gui_console_err_printf` and
  watch for `"Reset caused by"`, `"Reset triggered"`, `"writing to flash"`,
  `"protected memory"`, `"stack limit"` substrings. These map directly to
  `cpu_crash()` calls and the flash-protection checks in `core/mem.c`.
- To capture the exact faulting PC/registers (not just the post-reset state),
  snapshot `cpu.registers.*` **inside** the `gui_console_err_printf` hook the
  moment the fault message fires — by the time the harness's outer tick loop
  notices, several cascading resets may already have scrambled the state.
- Disassembly: `CE-Programming/zdis` (`gcc -std=c11 -DDEBUG_SUPPORT`) is a
  real eZ80/ADL disassembler and was validated against known-good code before
  being trusted for this investigation. Usage: `zdis --ez80 --start <decimal
  addr> --end <decimal addr> --compute-absolute --compute-relative <romfile>`
  (note: addresses are **decimal**, not hex, despite the flag names — this is
  a `zdis` test-harness quirk (`atoi()` on the CLI args), not a `zdis` API
  property).
- For ground-truth register values at an arbitrary code address (don't guess
  from crash side-effects — verify directly): rebuild `core` with
  `make CFLAGS="... -DDEBUG_SUPPORT"`, call `debug_init()` once, then
  `debug_watch(addr, DBG_MASK_EXEC, true)` per test case before running.
  Implement `gui_debug_open(reason, data)` (only exists under
  `DEBUG_SUPPORT`) to check `reason == DBG_BREAKPOINT && data == addr`, read
  whatever `cpu.registers.*` you need right there, then call
  `cpu_set_signal(CPU_SIGNAL_EXIT)` to cleanly end that test case's `emu_run`
  loop. This is far more reliable than inferring register state from delayed
  crash messages, which can be scrambled by cascading resets by the time your
  harness's outer loop notices.
