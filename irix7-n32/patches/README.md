# Patches

Two patches reproduce the n32 port from upstream sources.

## `relibc-n32.patch`

Applies to relibc upstream commit
`841d29c0c16dfa5c170f9208e7a6f93696802726` (2026-10-24), with submodules
initialised (`dlmalloc-rs`, `openlibm`).

```
git -C relibc apply /tmp/opencode/relibc-n32/patches/relibc-n32.patch
```

23 files, +224/−37. It includes the `Cargo.toml` switch from crates.io `sc` to
`vendor/sc`, so copy `vendor/sc` in before building (see below).

The changes, by area:

* `Cargo.toml` — move `redox-rings` and `redox-buffer-pool` to the Redox target;
  `sc = { path = "vendor/sc" }`.
* `src/lib.rs` — `#![feature(asm_experimental_arch)]`.
* `generic-rt/src/lib.rs` — `arch_read` via `rdhwr $29`; feature gate.
* `src/ld_so/tcb.rs` — MIPS `TLS_DTV_AT_TP` layout: TLS block + 0x7000 gap + TCB,
  `set_thread_area(tls_start + 0x7000)`.
* `src/ld_so/mod.rs` — read TP with `rdhwr`; static TLS module offset 0 on mips64.
* `src/ld_so/dso.rs` — MIPS relocation-kind stub, `__tlsdesc_static`, 32-bit
  `strtab_size` cast.
* `src/ld_so/linker.rs` — `__plt_resolve_trampoline` symbol for MIPS.
* `src/platform/linux/mod.rs` — `rlct_clone` for mips64 (MIPS clone argument order:
  `flags, stack, parent_tid, tls, child_tid`; `CLONE_SETTLS` + `CLONE_SYSVSEM`).
* `src/platform/types.rs` — `c_longdouble = u128` on mips64.
* `src/pthread/mod.rs` — extra stack padding word for 16-byte alignment.
* `src/header/setjmp/mod.rs` — wire `mips64` to `impl/mipsn32`.
* `src/header/setjmp/impl/mipsn32/sigsetjmp.S` — new tail wrapper.
* `include/setjmp.h` — 20-word `jmp_buf` for `__mips__`.
* `src/header/signal/linux.rs` — `__restore_rt` with n32 `rt_sigreturn = 6211`.
* `src/header/sys_mman/mod.rs` — `MAP_ANON = 0x800` on mips64.
* `src/header/sys_procfs/mod.rs` — placeholder mips64 `elf_gregset_t`/`elf_fpregset_t`.
* `src/header/netdb/mod.rs` — endian conversion branch for mips64.
* `src/header/stdio/printf.rs` — mips64 long-double vararg path.
* `src/header/stdlib/mod.rs`, `src/header/unistd/mod.rs`, `src/header/time/mod.rs` —
  32-bit `c_long` fixes.
* `src/casting.rs` — MIPS `c_char` is signed (`i8`).
* `Cargo.lock` — sc path dependency.

## `sc-n32.patch`

Applies to the crates.io `sc` 0.2.7 source (copy it to `relibc/vendor/sc` first).

```
cp -a /tmp/opencode/relibc-n32/build/sc/sc-0.2.7 /tmp/opencode/relibc-n32/relibc/vendor/sc
cd /tmp/opencode/relibc-n32/relibc/vendor/sc
patch -p1 < /tmp/opencode/relibc-n32/patches/sc-n32.patch
```

Changes:

* `src/lib.rs` — drop `feature(llvm_asm)` for mips64, add
  `feature(asm_experimental_arch)`.
* `src/platform/linux-mips64/mod.rs` — stable-`asm!` `syscall0..7`; `$2` syscall
  number, `$4`–`$9` arguments, `$7` error flag.
* `src/platform/linux-mips64/nr.rs` — 369 constants generated from the Bootlin
  `asm/unistd_n32.h` (base 6000). Note: n32 is not n64+1000 (140 relative
  differences), so do not reuse the n64 table.

## `apply.sh`

```
./patches/apply.sh
```

expects a fresh relibc clone in `relibc/` (upstream commit above), applies the relibc
patch, installs `sc` 0.2.7 from `build/sc/`, and applies the sc patch.

## Verification

`git apply --check` on a fresh clone and a byte-for-byte comparison of the patched
`vendor/sc` against this tree were used to validate both patches.
