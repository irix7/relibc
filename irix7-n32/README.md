# relibc n32 (mips64-linux-gnuabin32, big-endian) spike

**Verdict: feasible, and demonstrated end-to-end — but relibc upstream is not n32-ready.**
A patched relibc (23 files, +224/−37 lines, plus a vendored `sc` syscall backend) builds a
static big-endian n32 `libc.a`. Four static C smoke tests linked against it run under
`qemu-mipsn32`:

| Test | Result |
|---|---|
| `hello` + `printf` + argc/argv | **PASS**, exit 0 |
| `__thread` TLS (initial image + read/write) | **PASS**, `tls=1234` then `5678` |
| `setjmp`/`longjmp` (relibc's own mipsn32 asm) | **PASS**, `r=9` |
| `pthread_create`/`pthread_join` + per-thread TLS | **PASS**, child `tls=42`, main `tls=100`, `ret=43` |

No repository outside `/tmp/opencode/relibc-n32` was modified. `iri`/`/mnt/europa/os` were
never touched.

---

## 1. Environment and versions

| Component | Version / path |
|---|---|
| Host | Linux 6.18.55 x86_64 (NixOS) |
| Bootlin toolchain | `mips64-n32--uclibc--stable-2026.08-1`, GCC 15.3.0, GNU ld 2.45.1 |
| Toolchain URL | `https://toolchains.bootlin.com/downloads/releases/toolchains/mips64-n32/tarballs/mips64-n32--uclibc--stable-2026.08-1.tar.xz` (SHA-256 `9d05cfaa…35dd8`, verified) |
| QEMU | `qemu-mipsn32` 7.2.0, static build from `multiarch/qemu-user-static` v7.2.0-1 |
| Rust | `rustc 1.98.0-nightly (23a3312d9 2026-05-23)`, installed with rustup as relibc's pinned `nightly-2026-05-24` + `rust-src`; LLVM 22.1.6 |
| relibc | commit `841d29c0c16dfa5c170f9208e7a6f93696802726` (2026-10-24), submodules initialised |
| `sc` | 0.2.7 (crates.io), vendored and given an n32 backend |

ABI confirmed on every produced binary:

```
ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2, statically linked
Class: ELF32   Data: 2's complement, big endian
Flags: 0x80000025, noreorder, cpic, abi2, mips64r2
```

`sizeof(long)=4`, `sizeof(void*)=4`, `sizeof(long double)=16` under this toolchain.

---

## 2. Baseline: toolchain, QEMU, Rust target

These steps prove the environment independently of relibc.

### 2.1 C hello (Bootlin GCC + QEMU)

```sh
TC=/tmp/opencode/relibc-n32/toolchain/mips64-n32--uclibc--stable-2026.08-1/bin
$TC/mips64-buildroot-linux-uclibc-gcc -static -O2 -o hello-n32 hello.c
qemu-mipsn32-static ./hello-n32
# hello n32: sizeof(long)=4 ptr=4
# exit 42
```

### 2.2 Rust has no built-in n32 target

`rustc --print target-list` contains `mips64-unknown-linux-gnuabi64` (n64) but **no
`mips64-unknown-linux-gnuabin32`**. A custom target spec is required:
`build/mips64-n32.json` (in this tree), derived from the n64 spec with:

```json
"llvm-target": "mips64-unknown-linux-gnuabin32",
"llvm-abiname": "n32",
"target-pointer-width": 32,
"data-layout": "E-m:e-p:32:32-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128",
"relocation-model": "static",
"position-independent-executables": false,
"static-position-independent-executables": false,
"linker": "/tmp/opencode/relibc-n32/bin/cc-mips-dispatch"
```

The data layout was taken from `clang --target=mips64-linux-gnuabin32`; `llvm-abiname: n32`
is the field that makes LLVM emit n32 code. Cargo needs
`-Zjson-target-spec -Z build-std=core,alloc,compiler_builtins` (nightly). MIPS inline asm
additionally requires `#![feature(asm_experimental_arch)]`.

A minimal no_std Rust binary using `rdhwr $29` and direct `write`/`exit` syscalls built and
ran:

```
hello from rust n32
exit=0
```

### 2.3 Modern n32 syscall backend

`sc` 0.2.7 is dead on modern Rust for MIPS: its own source says only aarch64/riscv64/x86_64
were ported to stable `asm!`, and the mips64 module uses removed `llvm_asm!`:

```
error[E0635]: unknown feature `llvm_asm`
  --> sc-0.2.7/src/lib.rs:35:12
error: cannot find macro `llvm_asm` in this scope
  --> sc-0.2.7/src/platform/linux-mips64/mod.rs:19:5 (also 34, 49, 68, 87)
```

The n32 syscall table is **not** n64+1000. Comparing `asm/unistd_n32.h` with
`asm/unistd_n64.h`: 369 n32 entries, **140 relative differences**, e.g.

| syscall | n32 | n64 |
|---|---|---|
| `set_thread_area` | 6246 | 5242 |
| `set_tid_address` | 6213 | 5212 |
| `openat` | 6251 | 5247 |
| `newfstatat` | 6256 | 5252 |

`patches/sc-n32.patch` therefore generates all 369 constants from `unistd_n32.h` and
implements `syscall0..7` with stable `asm!`, explicit `$2`/`$4`–`$9` registers and the MIPS
error convention (`$7 != 0`). A standalone binary using this backend wrote and exited
correctly (`sc n32 syscall ABI ok`, exit 0).

### 2.4 Baseline pthread/TLS and setjmp on the toolchain

To separate QEMU capability from relibc:

* Bootlin uclibc static `pthread_create`/`join` + `__thread` works under `qemu-mipsn32`
  (`main tls=100`, `thread tls=42`, `ret=43`, exit 0).
* relibc's existing `src/header/setjmp/impl/mipsn32/setjmp.S`/`longjmp.S`, assembled and
  linked directly, work (`r=7 depth=1`, exit 0).

So the environment supports all four required capabilities; any failure below is relibc's.

---

## 3. relibc build: first blockers (upstream, unpatched)

A control build for x86_64 Linux with the same nightly succeeds:

```
Finished `release` profile [optimized] target(s) in 17.55s
librelibc.a  14 MB
```

The same build for `mips64-n32` fails in this order:

1. **Dependency graph pulls Redox-only crates into every target.** `redox-rings` and
   `redox-buffer-pool` are unconditional dependencies in `Cargo.toml`, and both depend on
   `redox_syscall`, which defines `arch` only for aarch64/riscv64/x86/x86_64
   (`kernel/syscall/src/lib.rs:7`, modules at lines 10–24). On mips64:
   `unresolved import self::arch`. The crates are used only by
   `src/platform/redox/ring.rs`, so they belong under
   `[target.'cfg(target_os = "redox")'.dependencies]`.
2. **No mips64 arch hooks in relibc.** `generic-rt` has `arch_read` only for
   aarch64/x86/x86_64/riscv64 (`generic-rt/src/lib.rs:88–89` call it unconditionally),
   `Tcb::os_arch_activate` only x86_64/aarch64 (`src/ld_so/tcb.rs`), and
   `ld_so::init` reads TP only on x86_64/aarch64/Redox (`src/ld_so/mod.rs:132+`).
3. **`sc` has no usable mips backend** (above).

After those, the crate itself produced **32 errors across 10 files**, all n32-relevant:

| Area | Evidence |
|---|---|
| `c_char` is `i8` on MIPS; casting helpers only listed x86 as signed | `src/casting.rs:27,57,77,104,124,154,180`; Rust core's unsigned-`c_char` list excludes mips |
| `c_long` is 32-bit on n32, but code assumes every non-x86 is 64-bit | `src/header/stdlib/mod.rs:1191`, `src/header/unistd/mod.rs:1401`, `src/header/time/mod.rs:232` |
| `long double` is 16 bytes; relibc picked the x86 `[u32;3]` for all 32-bit targets | `src/platform/types.rs:146–149`; printf had no mips `extract_longdouble` (`src/header/stdio/printf.rs:157`) |
| procfs register sets only defined for aarch64/riscv64/x86_64 | `src/header/sys_procfs/mod.rs:40,62,63` |
| endian conversion branch missed mips | `src/header/netdb/mod.rs:335` |
| no MIPS relocation mapping or TLS descriptor resolver | `src/ld_so/dso.rs:202,229,1200` |
| no pthread clone hook | `src/platform/linux/mod.rs:81`, `Pal::rlct_clone` |
| no mips64 crt0 `_start` | `src/crt0/src/lib.rs` (only aarch64/x86/x86_64/riscv64) |
| setjmp implementation not wired in | `src/header/setjmp/mod.rs` `platform_specific!` list; no `sigsetjmp.S` in `impl/mipsn32`; `include/setjmp.h` had no mips `jmp_buf` |
| MIPS `MAP_ANONYMOUS` is 0x800, relibc used 0x20 | `src/header/sys_mman/mod.rs` |

These are port gaps, not a build-system problem.

---

## 4. The n32 port applied here

`patches/relibc-n32.patch` (23 files, +224/−37) plus `patches/sc-n32.patch`.

Key changes, in the order they matter:

1. **Target/features:** custom JSON (§2.2); `#![feature(asm_experimental_arch)]` in
   `src/lib.rs` and `generic-rt`; static relocation.
2. **Dependencies:** moved `redox-rings`/`redox-buffer-pool` under the Redox target;
   replaced `sc = "0.2.7"` with `sc = { path = "vendor/sc" }`.
3. **Syscalls:** vendored `sc` with 369 n32 constants and stable-asm `syscall0..7`.
4. **TLS/TCB (the subtle part):**
   * MIPS n32 is `TLS_DTV_AT_TP`. glibc's
     `sysdeps/mips/nptl/tls.h` defines `TLS_TCB_OFFSET 0x7000` and
     `TLS_INIT_TP(tcbp) == set_thread_area(tcbp + 0x7000)`.
   * The linker emits `TP-0x7000` for a TLS symbol at module offset 0, even for a 4-byte
     TLS segment. Verified against a working uclibc binary (`tp - &x == 0x7000`).
   * `Tcb::os_new` now maps `page | TLS + 0x7000 gap | TCB page`, puts the TCB at
     `TLS_start + 0x7000`, and `os_arch_activate` calls
     `set_thread_area(tls_end - tls_len + 0x7000)`.
   * `arch_read` reads the TCB via `rdhwr $29`; `ld_so::init` reads TP the same way.
   * `STATIC_TCB_MASTER.offset` is 0 for mips64, so the image lands at TLS block start.
   * Without this, `__thread` read 0 instead of its initialiser (writes were
     self-consistent, which is the tell-tale sign of a wrong TP bias).
5. **pthread clone:** `rlct_clone` for mips64 uses the MIPS syscall order
   `clone(flags, stack, parent_tid, **tls**, child_tid)` — confirmed from glibc's
   `sysdeps/unix/sysv/linux/mips/clone.S`, which sets `a3 = tls` and `a4 = child_tid`.
   `CLONE_SETTLS` is required; `CLONE_SYSVSEM` is additionally required by QEMU's
   `do_fork` (`CLONE_THREAD_FLAGS` in `linux-user/syscall.c`). The child pops the frame
   pushed by `pthread::create` and calls `new_thread_shim`; the stack needs an extra
   padding word for 16-byte alignment (same trick as aarch64).
6. **crt0:** the smoke binaries use `build/relibc-hello/crt0.S`, which passes `$sp` and
   `main` to `relibc_start_v1`. Upstream `src/crt0` still needs the equivalent mips64
   `global_asm!`.
7. **setjmp:** added `mips64 -> mipsn32` to the `platform_specific!` list, added a
   `sigsetjmp.S` tail wrapper, and a 20-word `jmp_buf` in `include/setjmp.h`.
8. **Small ABI fixes:** `c_char` signedness, 32-bit `c_long` paths, 16-byte
   `c_longdouble`, `MAP_ANON = 0x800`, procfs register aliases, netdb endian branch,
   `__restore_rt` (n32 `rt_sigreturn = 6211`), PLT resolver stub, `strtab_size` cast,
   printf long-double vararg path.
9. **Linker dispatch:** `bin/cc-mips-dispatch` selects Bootlin GCC for n32 links and the
   host glibc GCC for build scripts, so cargo's host build scripts are not linked with the
   cross linker.

Result: `librelibc.a` 6.0 MB, build ~30 s from scratch (including build-std core/alloc).

---

## 5. Smoke tests (exact output)

Built with `build/relibc-hello/crt0.S`, `-mabi=n32 -march=mips64r2 -mno-abicalls -fno-pic
-nostdlib -no-pie`, linked against `librelibc.a` with `--start-group`.

```
$ qemu-mipsn32-static ./hello-n32
relibc n32 hello: argc=1 argv0=./hello-n32
exit=0

$ qemu-mipsn32-static ./smoke-n32
hello: argc=1 tls=1234
setjmp: r=9 jumped=1 tls=5678
formats: -7 42 123456789 -1234567890123 4 str A deadbeef 3.14 0x3ffe6008
exit=0

$ qemu-mipsn32-static ./pthread-n32
main: tls=100
thread: tls=42
joined: ret=43 main_tls=100
exit=0
```

The smoke test exercises `printf` (`%d %u %ld %lld %zu %s %c %x %.2f %p`), a static
`__thread` initialiser, modification and read-back, `setjmp`/`longjmp` with a non-zero
return, `pthread_create`/`pthread_join`, and TLS isolation between threads.

`logs/final-smoke.log`, `logs/pthread-trace7.log`, `logs/sc-n32.log` contain raw evidence.

---

## 6. Limitations / not production-ready

This is a working spike, not an upstream-quality port:

* **Static only.** Dynamic linking is untested. MIPS `RelocationKind::new` is a stub
  (`UNKNOWN`), `__plt_resolve_trampoline` returns 0, and the TLS descriptor resolver is a
  simple load. A shared `libc.so`/ld.so path needs real MIPS relocation and `TLSDESC`
  handling.
* **Signal/ucontext types are placeholders.** `elf_gregset_t`/`elf_fpregset_t` are
  `[u64; 32]` for compile purposes; `sigaction`, signal frames and `sigreturn` were not
  exercised. `__restore_rt` exists but is untested.
* **`long double` varargs are approximate.** `c_longdouble` is `u128` and
  `extract_longdouble` reads 16 bytes from a simple varargs cursor; `%Lf` was not tested.
  The MIPS varargs ABI may need register/stack-save-area handling.
* **Syscall argument ABI is simplified.** `sc` passes `usize` (32-bit) values; 64-bit
  arguments (`off_t`, `loff_t`) are truncated by relibc's call sites. Anonymous `mmap`
  (offset 0) and the tested paths are fine; large-file offsets are not.
* **Headers are incomplete for a C sysroot.** Only `include/setjmp.h` was needed and
  patched; there is no generated n32 header set, no `crt1.o` install, no `libpthread.a`
  symlink test. `Makefile`/`config.mk` have no mips entry.
* **crt0 not upstreamed.** The working `_start` is the 12-line `crt0.S` in the test dir;
  `src/crt0` still lacks mips64.
* **Warnings:** `ld` reports "linking abicalls files with non-abicalls files" for a few
  objects (`cgu.02`, `cgu.04`, `stdlib.o`). The tested paths work, but the mixed
  `$gp`/abicalls state should be cleaned up (drop `+xgot`, ensure `src/c` is built with
  `-mno-abicalls`, audit LLVM-emitted `.abicalls`).
* **QEMU 7.2 n32 specifics:** `CLONE_SYSVSEM` is required by QEMU's validator even though
  a real kernel does not require it; the clone TLS/child-tid register order had to follow
  glibc's MIPS `clone.S`. Re-test on real MIPS hardware/Linux before trusting.
* **Nightly only:** custom JSON + `build-std` + `asm_experimental_arch`. An upstreamable
  solution needs a built-in `mips64-unknown-linux-gnuabin32` target (or an accepted target
  spec) and a decision on MIPS asm stabilization.

---

## 7. What this means for forking relibc as the IRIX 7 C ABI layer

**The gate passes, with a bounded port.** The expensive unknowns — n32 codegen, static
linking, big-endian data, TLS layout, pthread clone, setjmp — are resolved and demonstrated.
The work is concentrated in an architecture seam that an IRIX PAL would need anyway:

* ~224 lines across 23 relibc files;
* an `sc`-compatible syscall backend (here 369 generated constants + ~180 lines of asm);
* TCB/TLS and clone hooks;
* crt0 and setjmp wiring;
* a handful of 32-bit type assumptions.

Recommended next steps, in order:

1. Upstream or carry the n32 target spec; add it to CI with Bootlin GCC + `qemu-mipsn32`.
2. Replace `sc` with a maintained n32-capable syscall crate, or upstream the vendored
   backend (generate constants from the kernel's `unistd_n32.h`, not n64+offset).
3. Add `src/crt0` mips64 `_start` and a `config.mk`/Makefile target.
4. Fix `c_char`/`c_long`/`c_longdouble`/varargs assumptions centrally (use
   `target_pointer_width` and explicit MIPS cfgs, not `target_arch = "x86"` as a proxy for
   32-bit `long`).
5. Implement MIPS dynamic relocations/TLSDESC if shared libc is required.
6. For IRIX 7, implement the PAL syscall layer behind the existing `Pal` trait; the
   architecture hooks above are reusable unchanged.

---

## 8. Layout

```
/tmp/opencode/relibc-n32/
├── README.md                 this report
├── bin/
│   ├── qemu-mipsn32-static   QEMU 7.2.0 user emulator
│   ├── cc-mips-dispatch      host/n32 linker dispatcher
│   └── cc -> host gcc        for cargo build scripts
├── toolchain/                Bootlin mips64-n32 uclibc 2026.08-1 (454 MB)
├── rustup/                   nightly-2026-05-24 + rust-src (1.0 GB)
├── relibc/                   patched relibc clone (upstream 841d29c) + vendor/sc
├── build/
│   ├── mips64-n32.json       Rust custom target spec
│   ├── relibc-hello/         crt0.S, hello.c, smoke.c, pthread.c + binaries
│   ├── setjmp-test/          standalone relibc mipsn32 setjmp asm test
│   ├── pthread-test/         uclibc pthread/TLS baseline
│   ├── hello/, sc-smoke/     toolchain and syscall baselines
│   └── target-check/         fresh rebuild used to validate this tree
├── artifacts/librelibc.a     built n32 relibc static library (6 MB)
├── patches/
│   ├── relibc-n32.patch      23 files, +224/−37
│   ├── sc-n32.patch          sc 0.2.7 → n32 backend + generated table
│   └── apply.sh              apply both to a fresh clone
└── logs/                     build logs, straces, final smoke output
```

The toolchain and rustup were originally placed on `/build` (tmpfs) because `/` was full;
they were copied here once space was available. `patches/apply.sh` documents how to
recreate the source state.

## 9. Reproduction (from this tree)

```sh
ROOT=/tmp/opencode/relibc-n32
TC=$ROOT/toolchain/mips64-n32--uclibc--stable-2026.08-1/bin
export PATH=$ROOT/bin:$TC:$ROOT/rustup/cargo/bin:$ROOT/rustup/rustup/toolchains/nightly-2026-05-24-x86_64-unknown-linux-gnu/bin:$PATH
export RUSTUP_HOME=$ROOT/rustup/rustup CARGO_HOME=$ROOT/rustup/cargo
export CARGO_TARGET_DIR=$ROOT/build/target-check
export CC_mips64_n32=$TC/mips64-buildroot-linux-uclibc-gcc
export CC_mips64_unknown_linux_gnuabin32=$TC/mips64-buildroot-linux-uclibc-gcc
export AR_mips64_n32=$TC/mips64-buildroot-linux-uclibc-ar
export AR_mips64_unknown_linux_gnuabin32=$TC/mips64-buildroot-linux-uclibc-ar
export CFLAGS_mips64_n32="-mno-abicalls -fno-pic -mabi=n32"
export CFLAGS_mips64_unknown_linux_gnuabin32="-mno-abicalls -fno-pic -mabi=n32"

cd $ROOT/relibc
cargo build --release --no-default-features \
  --target $ROOT/build/mips64-n32.json -Zjson-target-spec \
  -Z build-std=core,alloc,compiler_builtins

cd $ROOT/build/relibc-hello
$TC/mips64-buildroot-linux-uclibc-gcc -mabi=n32 -march=mips64r2 \
  -mno-abicalls -fno-pic -nostdlib -no-pie -Wl,-e,_start \
  -o hello-n32 crt0.o hello.o \
  -Wl,--start-group $CARGO_TARGET_DIR/mips64-n32/release/librelibc.a -Wl,--end-group
$ROOT/bin/qemu-mipsn32-static ./hello-n32
```

`bin/cc-mips-dispatch` uses `HOST_CC` (or the glibc GCC path recorded below) for host
build scripts. The host compiler used was
`/nix/store/j1938gsbvbhkyz4kbmvjk56r479mkw3s-gcc-wrapper-16.2.0/bin/gcc` (GCC 16.2.0,
glibc 2.44); any x86_64 glibc `cc` works.
