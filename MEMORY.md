# MEMORY — CVE-2026-43499 (GhostLock/IonStack) port: S25U(v6) → S22 Ultra/b0q (v5.10) in QEMU

Working dir (project root): `/home/sarab/v5-kernel/qemu/`
Updated: 2026-08-08. **Current state: FULL CHAIN GREEN ON THE REAL b0q DEVICE as unprivileged shell (uid 2000): CFS-nice trigger → CFI r/w → slide restore → pipe phys r/w → umh root daemon (`uid=2000->0`, `retval=0 socket=1`, attempt 1/16). Two device bugs fixed this session: the CFS payload tear (§4f) and the SELinux target (`SELINUX_ENFORCING_OFF` pointed at the inert `selinux_enforcing_boot`; now `selinux_state.enforcing`, off 0x028cccd8). Root usage: `/data/local/tmp/cve-2026-43499-root` (interactive) or `-c cmd` — there is no `su` on stock; the helper binary is both daemon and client. Remaining: stale-fops landmine on FAILED runs (§4f-panic note below), phys gate flakiness (§4e).**

---

## 0. Goal & status

Port GhostLock (CVE-2026-43499; `exploitinfo.txt` = Nebula writeup, Pixel/v6) to Samsung S22 Ultra
(**b0q**, taro/SD8G1, `5.10.226-android12-9-30958166-abS908WVLS8FYG7`), debugging in a modified QEMU.

- Exploit tree: `/home/sarab/v5-kernel/qemu/CVE-2026-43499-S25U/` (orig. S25U/6.6; `PORTING-NOTES-v5.10.md`).
- Working v5.10 reference: `/home/sarab/v5-kernel/qemu/IonStackQuest3/` (Quest 3 "eureka").
- **The pselect route is replaced by the exp32 route for s22** (§3): futex choreography + stack stamp +
  sched_setattr all run in a disposable 32-bit child — the TCG panic class is gone by construction.

## 1. ROOT CAUSE of recurring `ffffff8026fffXXX` panics — QEMU RKP pool bug (FIXED in qemu-src)

Both the original pselect-era panic (`ffffff8026fffab0`) and the later `copy_page_range` crash
(`ffffff8026fffaa8`) are **one QEMU emulation bug**:

- b0q allocates **every user pgd/pmd page from the hypervisor**:
  `s22/kernel_platform/common/arch/arm64/mm/pgd.c:30` `pgd_alloc() → rkp_ro_alloc()`,
  `arch/arm64/mm/mmu.c:269` `rkp_ro_alloc_phys(PMD_SHIFT)`, `mm/slub.c:1911`.
- Emulation (`qemu-src/target/arm/tcg/op_helper.c`) served `RKP_ROBUFFER_ALLOC` from
  `rkp_alloc_pool = 0xa7f00000` **counting down forever**; `RKP_ROBUFFER_FREE` was a no-op stub.
- Pool page **#3841 = `0xa6fff000`** = DTB carveout hole `[0xa6f00000, 0xa7000000)` (guest `/proc/iomem`).
  Clone storms eat thousands of pgds; the pool crosses the bank edge into the hole; the next
  `copy_page_range` walks a pgd entry pointing at `phys_to_virt(0xa6fff000)` → translation fault.
- Frozen-state evidence: crashing mm (`task+0x518 → mm=0xffffff87c6a9e180`) had
  `mm->pgd = 0xffffff80270f8000` = pool page **#3592**; the faulting load
  (`copy_page_range+320`, `ldr x8,[x21]`, x21=`0xffffff8026fffaa8`) reads a pmd entry in pool page #3841.
  Run-2 `TTBR0_EL1=0xa770c000` = pool page #2044. Every user pgd in the guest is a pool page.
- Pool pages in-bank were also never reserved → buddy double-allocation hazard.

**Fix (qemu-src, built + swapped in 05:42):**
1. `target/arm/tcg/op_helper.c`: bounded bitmap allocator over `[0xa7000000, 0xa7f00000)` (15 MB / 3840
   pages) + real `RKP_ROBUFFER_FREE` recycling; exhaustion returns 0 (kernel → ENOMEM, graceful).
   `RKP_GET_RO_INFO` returns real base/size. `LINEAR_MAP_VOFFSET` corrected to `0xffffff7f80000000`.
   **Pool pages are ZEROED on every alloc** — b0q has no `pgd_ctor` and `pgd_alloc()/rkp_ro_alloc()`
   does no memset (bypasses `__GFP_ZERO`), so the hypervisor must hand clean pages. Crash #3
   (`copy_pte_range+140`, pmd entry → gap phys `0x7C9724XXX`) was a recycled-but-dirty pool page.
2. `hw/arm/virt.c` (`virt_modify_dtb`): `/reserved-memory/rkp_pool@a7000000` (`reg 0xa7000000+0xf00000`,
   no `no-map`) — reserves pool from buddy, keeps it linear-mapped (like the device's real carveout).
- Binary swapped in: `qemu-system-aarch64-static-pc` (zeroing included). Old: `…static-pc.bak-rkpool`.
- Crash #3 run confirmed the new allocator was active (pgd at pool index 232 bottom-up).
- Next: reboot guest; `/proc/iomem` shows pool reserved; fork-storm without exploit; rerun exploit.

## 2. Original panic analysis (kept; the pselect-route TCG race)

The first reported panic (`ffffff8026fffab0`, ESR 0x96000007, task T5893 = pselect consumer) was the
pselect route's own race: the consumer must fire `sched_setattr` while the waiter is inside pselect;
under TCG it fired after `do_select`'s return writeback clobbered the stale waiter → chain walk on
garbage → wild read into the carveout hole. (Same hole because garbage content then held pool pointers —
see §1.) The exp32 route removes this race entirely. Real-device ctrl-c panic
(`dumpstate_latest_lastkmsg.log`: `rt_mutex_adjust_prio_chain+0x184`, junk ptr `f0a52dc0081e308c`) was
the same walk on torn state.

## 3. exp32 port for s22 (DONE)

Files in `/home/sarab/v5-kernel/qemu/CVE-2026-43499-S25U/`:
- `src/exp32/main.c`, `src/exp32/stack.c` — 32-bit stage (armhf static). **Stamp offset `buffer+0x58`**
  (b0q, §10). **Stamp-then-park**: 64 stamps, then a pure userspace spin (no syscalls), only then
  `g_consumer_go=1` — fixes crash #1 (memset zero-window: consumer fired while `do_ipv6_setsockopt`
  had `gr32` memset to 0 → `trylock(NULL)` at `rt_mutex_adjust_prio_chain+388`; confirmed via crash
  pt_regs + waiter dump showing a perfect payload — offset itself was correct).
- `src/api.c` — `exp_stack_once()` (memfd payload + fork/exec); drop path `/data/local/tmp` else `/tmp`;
  self-installs blob.
- `src/exp32_blob.S` — `.incbin "build/embed/cve_exp32_arm32"`.
- `src/common.h` — `PAGE_PAYLOAD_EXP32`, `fake_fops_request/done`, new decls.
- `src/util.c` — EXP32 payload branch: zeroed fake_lock, detached fake_task (s22 offsets), fops table
  with **`.llseek = 0`** (rb collateral takes +0x08; repaired later); EXP32 gets FOPS retry count;
  log label `main=exp32`.
- `src/targets/s22/main.c` (new) — Quest3 flow: `cfi_thread` loops `try_cfi_stage`; main loop:
  `prepare_good_kernel_page(PAGE_PAYLOAD_EXP32)` → `doreplacefops()`; payload words:
  `pc=fake_fops, right=0, left=kaslr_image_addr(ASHMEM_MISC_FOPS), task=fake_task, lock=fake_lock`.
- `src/targets/s22/fops.c` — pselect route deleted; `try_cfi_stage` calls `repair_fake_fops_llseek()`.
- `Makefile` — 32-bit build (`arm-linux-gnueabi-gcc -static -pthread`; NDK fallback), embed into PRELOAD.
- Build: `make PROJECT=s22 USE_BUILDROOT=1 clean preload root-helper` →
  `build/s22-qemu/bin/cve-2026-43499` (label `b0q_taro_v5.10`). Run: `LD_PRELOAD=/tmp/cve-s22 sh`.
  (A `qemu_aarch64_virt_v5.10`-labeled binary is the WRONG target — slide offsets don't match b0q.)

Write mechanics (verified on b0q `kernel/locking/rtmutex.c:663`): chain walk step [7]
`rt_mutex_dequeue(lock, waiter)` is unconditional → `rb_erase_cached(&waiter->tree_entry, …)` with
`pc=fake_fops(RED), right=0, left=target` → `rb_set_parent(child=target, parent=fake_fops)` writes
`*target = fake_fops | (*target & 1)` (= fake_fops, ashmem_fops is 8-aligned); collateral:
`__rb_change_child` writes target into `fake_fops+0x08` (.llseek) → repaired via
`repair_fake_fops_llseek` (pread/pwrite don't use .llseek, so the repair can come after first r/w test).

## 4. Verified test runs (chronological)

1. exp32 chain completes under TCG with no panic (`…CMP_REQUEUE_PI… → exploit chain complete`).
2. CFI stage failed on missing `/dev/ashmem` → created from `/proc/misc` (`c 10 123`); persistent
   init script **`/etc/init.d/S99cve`** installed (ext2 rootfs AND both cpio initrds
   `s22/rootfs{,-defex}.cpio.gz` — backups `*.bak-cve`).
3. Crash #1: memset zero-window (`trylock(NULL)` @ `rt_mutex_adjust_prio_chain+388`) → stamp-then-park.
4. Crash #2: `copy_page_range+320` bad pmd into `0xffffff8026fffaa8` → RKP pool underflow (§1) → fixed.
5. Crash #3: `copy_pte_range+140` pmd entry → gap phys `0x7C9724XXX` → recycled pool pages not
   zeroed on alloc → fixed (§1).
6. Crash #4 (two hits): `rt_mutex_adjust_prio_chain+388` trylock on junk `waiter->lock` —
   (a) `x27=0` (memset zero-window, old loop) → stamp-then-park; (b) `x27` = PAC-signed
   `put_prev_entity` LR in `waiter->lock` — CFS tick preemption of the parked userspace-spinning
   waiter reusing its kernel stack. FIFO-at-start didn't fully fix it: the consumer's SCHED_BATCH
   flip moved the waiter BACK to CFS inside sched_setattr's own window, and the tick clobbered the
   payload before the walk read it (TCG stretches the window). **Final trigger: RT-priority DROP
   (FIFO 99→98)** — `rt_mutex_adjust_pi` runs for any sched_setattr (`sched/core.c:5784` pi=true),
   and the waiter stays in RT class → no CFS preemption can ever clobber the payload.
   Live proof via gdb: payload at `rt_mutex_adjust_pi` entry is perfect (`pc=fake_fops`,
   `left=ashmem_misc.fops`, `lock=fake_lock`, prio 139 vs 0); the dequeue write path is
   source-verified (rtmutex.c:663 → `rb_erase` at `+1260`; RB_EMPTY check at `+1180`).
   NOTE: FIFO needs root — QEMU guest is root; real device (shell) needs another stabilization.
7. BUILD GOTCHA (cost a day): after the `stack.c` stamp-then-park edit, the embed rebuild **failed
   silently** (`yield` unsupported by `arm-linux-gnueabi-gcc` default ARM mode) and the pipeline hid
   the error → the guest kept running the stale 10M-loop blob (sha `18a7667a`). Always verify
   `sha256sum build/embed/cve_exp32_arm32 build/s22-qemu/bin/cve-2026-43499` after building.
   Current good build: embed `18955aa3`→`63a6b5cc` (RT-drop), .so `3eaa68c6`.

## 4b. RESOLVED — mm-slab reclaim was failing because the BUDDY split the freed page (2026-08-06)

**Old hypothesis (wrong):** "leaked mm slab never discarded to buddy." GDB tracing disproved it —
the drain works perfectly every attempt. The real bug was one step later.

**What actually happened (per attempt, all GDB-verified):**
1. `close(memfd_leak)` → leak slab frozen on cpu-partial, `inuse=0` (FREE_FROZEN path).
2. Late drain (close 1 obj per prepare slab) → `__slab_free` CPU_PARTIAL_FREE path
   (slub.c:3270) → `put_cpu_partial(drain=1)`; once accumulated `pobjects > cpu_partial(13)`
   → `unfreeze_partials` → leak slab `inuse==0 && nr_partial(≥12) >= min_partial(5)`
   → `DISCARD` → order-3 page lands on buddy `free_area[3]`. ✓ (exactly one DISCARD per
   attempt, always the leak slab — verified via `page->slab_cache == mm_cachep` and
   two-point VA mapping).
3. **THE BUG:** within the drain→send window, an order-0 PCP refill
   (`rmqueue_bulk` ← `__rmqueue_pcplist` ← `get_page_from_freelist`) found `free_area[0]`
   (UNMOVABLE) empty and **split our order-3 page into 8 order-0 pages**, which were
   immediately handed out as PTE/anon pages (`copy_pte_range` from the exploit's own fork
   churn, `handle_pte_fault`, `do_wp_page`, `zap_pte_range`). The 32 skb sends (order-3
   frag pages via `sock_alloc_send_pskb(..., get_order(UNIX_SKB_FRAGS_SZ)=3)`) therefore
   reclaimed *other* pages, never ours. `fake_lock`/`fake_fops` pointed at live
   pagetables → walk either spins on garbage `wait_lock` (RCU stall + workqueue lockup,
   the original report) or bails clean (`chain complete` + `cfi misc_fops mismatch
   read=0`). Both failure modes = same cause.

**Fix (util.c):** `prefill_order0_buddy()` — mmap/touch/munmap 16 MB (env
`RECLAIM_ORDER0_MB`, 1..256) right after `close(memfd_leak)`, before the drain closes.
Tops up `free_area[0]`/PCPs so nothing needs to split the leak page before the skb frags
grab it. Build: embed unchanged `63a6b5cc`, .so `16848e40`.

**Result:** full chain fires through CFI: `cfi write ret=35`, `cfi read ret=35`, slide
restore ok, pipe page leak + reclaim + phys gate `match=1`, `probed write ok=1`.
Remaining blocker moved to the phys READ path — see §4c.

**How it was found (gdb-mcp tracepoint recipe, reusable):**
- Corrected symbol addrs for THIS Image (the ones noted before were stale):
  `put_cpu_partial=0xffffffc008461f6c`, `unfreeze_partials=0xffffffc00846414c`,
  `discard_slab=0xffffffc008464700`, `__slab_free=0xffffffc008460e6c`,
  `mm_cachep` symbol `0xffffffc00a798188` holds a POINTER; the struct lives at
  `0xffffff8780002600` (boot memblock alloc, stable across nokaslr reboots).
- mm_cachep struct offsets (KASAN build): `min_partial=5` @+0x10, `size/object_size=960`
  @+0x18, `offset=0x1e0` @+0x28, `cpu_partial=13` @+0x2c, `oo=0x00030022` (order 3,
  34 objs) @+0x30, `node[0]` @+0x100 → `0xffffff8780000800`; `kmem_cache_node.nr_partial`
  @+0x8. `struct page`: `slab_cache` @+0x18, `freelist` @+0x20, `counters` @+0x28
  (inuse = low16, frozen = bit31). `kmem_cache_cpu.partial` @+0x18.
- Tracepoints (hw breaks, `silent`+printf+`cont`, cond `$x0==0xffffff8780002600`):
  put_cpu_partial entry (log page/drain), unfreeze_partials entry (log chain/node/
  nr_partial), **decision point** at `unfreeze_partials+220` (`tst x23,#0xffff`; regs:
  x22=page, x23=new.counters, x27=node; cond `$x19==mm_cachep`), discard_slab entry.
- The kill shot: hw **write watchpoint on the discarded page's `struct page`+0x28**,
  armed while stopped at the discard_slab breakpoint → backtraces caught
  `rmqueue_bulk` splitting it and `copy_pte_range` et al. consuming the pieces.
- Page↔VA ground truth (two discard-verified pairs): **true `VMEMMAP =
  0xfffffffefde00000`**; `pfn = (va - PAGE_OFFSET + memstart_addr) >> 12`,
  `memstart_addr = 0x80000000` (read from kernel symbol), `sizeof(struct page) = 0x40`.

## 4c. CURRENT BLOCKER — phys read path reads the wrong address (2026-08-06)

- After the §4b fix: `phys step probed write ok=1` but `probed read ok=0`;
  `read64 ok=0 value=5f6365737562656e` = ASCII `"nebusec_"` — a real kernel string from
  the WRONG location. Guest also logs `Trying to vfree() nonexistent vm area` (T424).
- Translation bug map (all verified against the two §4b ground-truth pairs):
  - `target.h VMEMMAP_START = 0xfffffffeffe00000` is **+0x2000000 too high**
    (true `0xfffffffefde00000`). `util.c track_mm_page` uses the correct pfn formula
    (incl. memstart) → its printed page is +0x2000000 high (diagnostic-only).
  - `pipe.c` va→page (pipe.c:342) **omits memstart**: pfn +0x80000 → page +0x2000000 —
    exactly cancels the VMEMMAP overshoot, so pipe.c page↔va is *accidentally correct*.
  - ⇒ the phys-read asymmetry is NOT the plain page math: write side used
    `pipebuf=base` (raw leaked VA) and worked; read side must compute the address
    through a different helper/constant. Next: diff the read64 vs write64 paths in
    `pipe.c` (offsets into the page, phys→va direction, or the probe gate values
    `n2k/c2k`), then fix and also correct `VMEMMAP_START` + document the pipe.c
    memstart cancellation so they don't get "fixed" independently later.

## 4d. RECLAIM MISS → stale misc.fops → `die@misc_open` (2026-08-07, fix applied)

Run: all attempts failed `cfi misc_fops mismatch ret=-1 read=0 errno=25`, then the
guest **died** during a later attempt. GDB post-mortem (stopped at `die`):

- `ESR_EL1=0x8a000000` = PC alignment fault; `ELR=FAR=0xffffff87d37f03c1`.
- Call site `misc_open+292`: `ldr x8,[x24,#112]; blr x8` = `f_op->open` dispatch,
  with x24 = `ashmem_misc.fops` = `0xffffff87d37f0180` = **attempt #4's fake_fops —
  still installed**. The step-4 mismatch fail path (`dirty=0`) never restores misc.fops.
- Page `0xffffff87d37f0000` held **live recycled mm_structs** (saved_auxv AT_* pairs,
  user VAs). `f_op->open` = `*(page+0x1f0)` = junk `0x...3c1` → `blr` → die.
  Crashing task = `sh` (exploit main pid) in a later attempt's `open("/dev/ashmem")`.
- Attempt #10's page (`0xffffff87c8d08000`) was also fully recycled at crash time.

Root-cause chain:
1. **Reclaim missed the leak page on every attempt.** The send→drain cycling only
   ever pinned the single final head page; b0q buddy frees insert at TAIL /
   shuffle-random positions (the util.c:772 comment already knew this), so capture
   was a per-attempt coin flip. §4b's good run simply won the flip.
2. A missed page floats in the buddy; the exp32 child's own fork/exec (api.c)
   allocates fresh mm_structs from it → **payload destroyed between the rb-write
   and the CFI open**.
3. The walk still occasionally lands on a junk-but-zeroed fake_lock (attempt #4)
   → misc.fops hijacked to a junk table.
4. Every `configfs_read_once` SET_NAME ioctl then sees `f_op->unlocked_ioctl==NULL`
   → ENOTTY(25) → `mismatch read=0`. **The arb-write was never the problem** — the
   verify read was dispatching through a dead table. (Separate from §4c's probe-read
   bug.)
5. Next attempt's open with the stale table: NULL `.open` → survivable ENOTTY;
   nonzero junk `.open` (attempt #10) → `blr` → PC alignment fault → die.

Fix (util.c `prepare_kernel_page`, s22 reclaim — committed as **b08ab8c**), three parts:
1. **Buddyinfo-driven absorb** in `order3_hold_begin()`: drain zone Normal's
   `free_area[3]` to near-empty (read `/proc/buddyinfo` per pair; target 0, cap
   `RECLAIM_ABSORB_MAX_PAGES`=4096 / 768 pairs) BEFORE the late drain, so the
   discarded leak page lands on a near-empty list and the first sends take it
   from the head. Pile released per round AFTER capture (run-3 showed persistent
   pile saturates the 512-pair cap by round 3 → zero absorb, and EMFILE by round 8).
2. **Hold-all, never-closed batches**: reclaim sends stay queued undrained
   (`SKB_DRAIN_SENDS=1` restores drain-cycling) on a ring of 64 8-pair batches
   (`reclaim_batch_next()`; a batch closes only on wraparound) — a stale misc.fops
   left by a failed round keeps dispatching into a LIVE payload table (valid JT
   .open/.release) instead of a recycled page. Zero-init guards so cleanup paths
   can't close() fd 0.
3. **THE ACTUAL THIEF (live-proof)**: even with 1+2 the payload never landed.
   Write-watchpoint on the discarded leak page caught the first writer:
   `clear_page ← kernel_init_free_pages ← kmalloc_order ← tracing_open ←
   do_sys_openat2` — **`track_mm_page(base, "drained")`'s tracefs open did a
   zeroed order-3 kmalloc that stole the leak page right after the discard,
   every attempt** (and the kprobe read always failed anyway — pure own-goal).
   `RECLAIM_MM_TRACK` now defaults to 0; the "drained"/"sent" tracks moved
   post-capture (they can only steal a harmless split-remainder there).

**Live verification (run 4, 2026-08-07):** discard bp + page watchpoint showed
`skb_copy_datagram_from_iter ← unix_stream_sendmsg` writing the fops JT table
into the leak page (`x0=leak base`, `x9/x10=configfs JT addrs`); then
`cfi write ret=35`, `cfi read ret=35`, `slide restore boot_id … after=want` ✓.
Note: `clear_page` firing on a captured page is BENIGN — b0q has init_on_alloc
(zeroes every alloc); it is the send's own frag allocation. Also explains why
"recycled" pages always looked zeroed rather than poisoned.

**Side issues seen in run 3 (not blocking now, revisit if they recur):**
- `RKP pool EXHAUSTED` during heavy clone spray (bounded 3840-page pool vs
  ~1360 concurrent children × pgd+pmd pool pages) — QEMU-side, pool sizing/recycling.
- EMFILE when the pile was process-persistent — fixed by per-round release (fix 1).

Fix builds: embed unchanged `63a6b5cc`; .so `33239a5c` (final, committed).

## 4e. CURRENT BLOCKER — pipe phys gate reads slab_cache=0 (2026-08-07)

Run 4 (with the §4d fixes): CFI clean, then the pipe stage leaks the skb page
(`base=ffffff87cf6a0000`) but the cache gate fails on all 8 sub-page offsets:
`phys gate caches n2k=ffffff8780003680 c2k=0460000000000f82 pipe=0460000000000f82`
then `phys gate off=NNN head=ffffffff1f1da8NN slab_cache=0000000000000000 match=0`
→ `phys step cache gate failed slab=0 want=0460000000000f82`.
- The gate reads `page->slab_cache` (+0x18) via the phys-read path and gets 0.
  Two candidate causes, in order of likelihood:
  1. **§4c's phys-read translation bug** (read64 hits the wrong address) — the
     gate's `head=` values must be re-derived with true VMEMMAP `0xfffffffefde00000`.
  2. The gate's expectation is wrong: an skb frag page is NOT a slab page, so
     `slab_cache` is legitimately 0 unless the pipe-page reclaim put it inside a
     slab — check what c2k/pipe `0x0460000000000f82` actually is (looks like
     page->flags/counters, not a kmem_cache pointer).
- Next: read `pipe.c` (gate + read64/write64), re-run with the gate address math
  printed against the true VMEMMAP, then fix §4c properly (VMEMMAP_START in
  target.h + document pipe.c's memstart cancellation).

## 4f. RESOLVED — CFS-path payload tear was the exploit's OWN post-stamp printf (2026-08-08)

**Verdict (gdb-mcp live capture, `cfs-debug.gdb` = INIT_W + STAMP + TRIG probes):**
hypothesis **(b) confirmed, (a) killed** — 64× STAMP slot `0xffffffc00b303c60` ==
TRIG `pi_blocked_on` exactly (the +0x58 offset is right for the exploit's real
WRPI path), but the TRIG dump held frame garbage, not the payload.

**The writer was NOT the scheduler.** The torn slot held a `file_tty_write`
frame record (saved x29 = stack self-ptr at +0x10, saved x30 at +0x18 =
`file_tty_write+664` = return after `bl ldsem_up_read`; callee-saved tty/heap
ptrs at +0x00/+0x30/+0x38). The uncommitted device-bringup edit had added the
`pr_warning("stamp: %d/%d setsockopt failed ...")` diagnostics AFTER the
64-stamp loop and BEFORE `g_consumer_go=1` — that `write()` to the console tty
re-enters the kernel on the waiter's own stack and lands exactly on the stale
waiter slot, tearing the payload between the last stamp and the walk.
Deterministic on every attempt → device panic `waiter->lock=1` (adb pty write
path, different frame garbage), QEMU flaky/panicky (ttyAMA frames). The RT path
stayed green because the known-good RT build (b08ab8c) predates that edit.

**Fix (stack.c, in the uncommitted device-bringup set):** probe ONE stamp and
print the result FIRST, then the 64 real stamps, then park. HARD INVARIANT: no
syscalls of any kind between the last stamp and the park — not even a printf.
**Verified live (QEMU, CFS-nice trigger, no EXP32_RT):** TRIG dump = perfect
payload (all 6 words match), `chain complete`, `cfi write ret=35`,
`cfi read ret=35`, slide restore green, pipe stage reached. Residual race: a
CFS tick preempting the parked spin in the [last-stamp → walk] window leaves
schedule() frames on the slot (the §4.6(b) mechanism) — µs-wide on device,
stretched under TCG; covered by retries; EXP32_RT eliminates it entirely.

**New gdb-mcp gotcha (cost an hour):** `$sp_el0` & co. are VOID-typed sysregs
in this gdb — CLI arithmetic/casts fail ("Argument to arithmetic operation not
a number or boolean" / "Invalid cast") and an error inside a breakpoint
command list ABORTS it, so the trailing `cont` never runs → target silently
stays stopped. Workaround in `cfs-debug.gdb`: a Python `gdb.Function`
`$cur()` = `int(frame.read_register('SP_EL0')) & 0xffffffffffffffff`.
Stamp-copy probe site: `do_ipv6_setsockopt+600` = `0xffffffc0094e96d4`
(`bl _copy_from_user`; x0=gr32 dst, x26=optname, x22=optlen; the fatal memset
is at +560). `$cur()` comm check confirmed the stamping thread = `cve-exp32`.

## 4g. DEVICE RUN LOG (2026-08-08, two boots) — success + the dmabuf_dump panic

Boot A (panicked ~139s after the run): attempt 1 fully green (CFI, phys,
`read64 ok=1 "nebusec0"`) until the root stage: `umh retval=-13` (EACCES) →
retry → attempt 2 reclaim-miss → `cfi misc_fops mismatch ... errno=25`
(dirty=0 → misc_fops left pointing at a recycled page, CAN'T be restored via
the dead fd) → later `dmabuf_dump` (pid 2153) panicked: `seq_show+0x220`
= the fdinfo `show_fdinfo` call site (`blr x8`, x8=`file->f_op+0xe0`,
f_op+0xe0 = `.show_fdinfo`) with x8=**0x3ff**. dmabuf_dump periodically
scans `/proc/*/fdinfo/*`; a file whose f_op dangles into a recycled exploit
page dispatches garbage → PC alignment → fatal. Same landmine CLASS as §4d
(misc_open), different trigger (fdinfo read). **Lesson: any run that fails
after the walk arms a system-wide landmine; only the success path defuses it
(restores misc_fops). The success-path "stability keeper" retaining reclaimed
pages is load-bearing.**

Boot B (FULL SUCCESS): helper was 777 all along; the -EACCES was SELinux.
Fixed `SELINUX_ENFORCING_OFF` (was `selinux_enforcing_boot` 0x02548484 —
boot-time-only, writing it is a runtime no-op; now `selinux_state.enforcing`
0x028cccd8, offset proven via `sel_write_enforce`'s `ldaprb/strb [x22]`,
struct is `__randomize_layout` so never assume). Run: `enforcing byte 1 -> 0`,
`umh retval=0 socket=1`, `uid=2000->0`, keeper pid spawned, attempt 1/16.
Root shell: `/data/local/tmp/cve-2026-43499-root` (client+daemon in one
binary; `-c cmd` for one-shots; socket `/data/local/tmp/temp_su.sock`).
Also added root.c diagnostics: helper stat/X_OK log + enforcing readback log.

## 4h. DEVICE BRING-UP — original notes (2026-08-07 evening, superseded by §4f)

Goal: run as Android `shell` (uid 2000, `u:r:shell:s0`, SELinux enforcing) on the
real b0q. Device build = `make PROJECT=s22 clean preload root-helper` (NDK/bionic;
outdir `build/s22/bin/`). The USE_BUILDROOT glibc .so loads only in the QEMU guest.
Landed device fixes (uncommitted): `pin_to_core` falls back into the allowed mask
(shell cpuset excludes cores 2,3 → fell back to 6/4; EINVAL no longer fatal);
consumer trigger defaults to a **CFS nice bump** (RT drop needs CAP_SYS_NICE, which
shell lacks — `EPERM`; `EXP32_RT=1` restores the RT path); `CONSUMER_DELAY_USEC`
15ms → **0** (the 15ms guaranteed a tick clobber on device).

**Root symptoms (device, log.txt ×2 boots):** panic at
`rt_mutex_adjust_prio_chain+0x184` (= **+388**, the §4.6 junk-lock trylock site),
`waiter->lock = 1`, called from the consumer's `sched_setattr` (CPU 4). QEMU CFS
runs are flaky: `cfi misc_fops mismatch ret=0` (real-ashmem EOF → write never
landed) or pass — and a trigger-time gdb dump showed the stale waiter slot holding
**live futex-frame content** (real pointers + a PAC-signed LR at +0x18), NOT the
payload. So on the CFS path the payload is not resident at the stale waiter when
the walk fires. The RT path (waiter un-preemptible) is unaffected — still green.

**Facts established while debugging (don't re-derive):**
- `errno=99 (EADDRNOTAVAIL)` from the stamp's `setsockopt` is **harmless and
  expected on both QEMU and device**: it's the `ss_family != AF_INET6` check at
  `ipv6_sockglue.c:173`, which runs AFTER the compat copy (`:169`) that performs
  the stamp. The stamp executes in both. (SELinux/EACCES theory ruled out.)
- The walk's stale waiter is at `task->pi_blocked_on` (+0x898), which on 5.10 is
  a `struct rt_mutex_waiter *` (not the lock). QEMU dumps put it at the canonical
  stack slot `…c60`.
- Trigger-capture recipe: hw bp at `__sched_setscheduler+3544`
  (`0xffffffc008133c18` = `bl rt_mutex_adjust_pi`, task in `x19`) with condition
  `*(long*)($x19+0x898) != 0` → fires only for sched_setattr-driven walks
  (rt_mutex_adjust_pi is also hit from futex-internal paths). Scripts:
  `trig-dump.gdb`, `init-waiter-map.gdb` (rt_mutex_init_waiter = 0xffffffc0081890a4).
- **gdb-mcp gotcha:** deleted hw breakpoints can stay programmed in per-CPU DBG
  registers → phantom SIGTRAPs at stale addresses with no listed bp. Fix: zero
  `DBGBCR0-5_EL1`/`DBGWCR0-5_EL1` on every thread (1.1–1.8), then disable+enable
  the live bps (the mass-clear also disarms them). Verified the trap at
  rt_mutex_adjust_pi+20 was a hw register leftover, not a patched BRK.
- kallsyms.txt (oofset-extractor) is misaligned vs the live kernel — trust gdb
  symbolization only.

**Open question / next debug step:** why the payload isn't resident at the stale
waiter at CFS-trigger time. The stamp demonstrably covers the slot (§4.6 verified
perfect under RT), and the park makes no syscalls. Two hypotheses to split with
the init-waiter map: (a) the walk's `pi_blocked_on` VA ≠ the stamp's `gr32+0x58`
(offset assumption wrong for the exploit's exact WRPI path vs the probe32
measurement); (b) a writer tears the slot between the last stamp and the walk —
catch it with a write-watchpoint on `slot+0x38`, writer PC will name it.
If (b) shows scheduler frames despite the shallow park, consider parking the
waiter in a shallow blocking syscall instead of the userspace nop loop.

## 5. QEMU fork inventory (qemu-src)

Repo `/home/sarab/v5-kernel/qemu/qemu-src/` (built binary `qemu-system-aarch64-static-pc`,
build dir `build-static-pc/`):
- `hw/arm/virt.c`: VIRT_MEM=2 GiB; ram-low 2 GiB @0x80000000 + ram-high @0x800000000; `virt_modify_dtb`
  injects 10 Qualcomm banks (verified == guest `/proc/iomem`); fake 4+3+1 clusters, MPIDR `idx<<8`,
  `qcom,kryo`; (+ new: rkp_pool reserved node, §1).
- `hw/arm/boot.c`: kernel loaded at `0x80000000+0x28000000−2MiB` → `_text` phys `0xa8000000` (matches
  device + exploit p0 `delta=0x28000000`); EFI-stub size fix; DTB placement.
- `target/arm/tcg/cpu64.c`: ID_AA64ISAR1 TS/FlagM field disabled (harmless).
- `target/arm/tcg/op_helper.c`: Samsung UH (RKP/KDP) emulation (~485 lines) — now with the fixed
  bounded pool allocator (§1). Guest accesses via `cpu_memory_rw_debug`; early-boot fallback constants
  only matter pre-pagetables (LINEAR_MAP_VOFFSET fixed; KIMAGE_VOFFSET ok).

## 6. b0q kernel facts (verified)

- Config `s22/config.txt`: `CONFIG_COMPAT=y`, `CONFIG_IPV6=y`, VA_BITS_39 (4K pages), MTE, CFI_CLANG,
  VMAP_STACK, SLAB_FREELIST_RANDOM/HARDENED, SHUFFLE_PAGE_ALLOCATOR, DEBUG_LIST, HARDENED_USERCOPY,
  **no** RANDOMIZE_KSTACK_OFFSET, TRACEFS_DISABLE_AUTOMOUNT, KPROBES(+EVENTS).
- Layout: PAGE_OFFSET `0xffffff8000000000`; kernel image `0xffffffc008000000` (slide 0 in QEMU;
  device slide varies e.g. `0x108000`); kernel phys `0xa8000000`. `__va = PO + phys − memstart`.
- Source: `s22/kernel_platform/common/` (GKI 5.10 + Samsung backports; modern futex split present).
- Symbols/vmlinux: `oofset-extractor/vmlinux` (kallsyms names, no DWARF); `s22/vmlinux.kallsyms.elf`.
- Key addrs (slide 0): `futex_wait_requeue_pi=0xffffffc008229784`, `do_futex=0xffffffc008224b14`,
  `rt_mutex_adjust_prio_chain=0xffffffc008187458` (+388 = trylock site),
  `rt_mutex_init_waiter=0xffffffc0081890a4`, `rt_mutex_wait_proxy_lock=0xffffffc008189614`,
  `copy_page_range+320=0xffffffc0083fce64`, `__arm64_sys_setsockopt=0xffffffc009254760`,
  `ipv6_setsockopt=0xffffffc0094e93a8`, `do_ipv6_setsockopt=0xffffffc0094e947c`,
  `ashmem_misc.fops=0xffffffc00a6ec728`, `init_task=0xffffffc00a59c000`.
  `task_struct.comm @ +0x790`; EL1 `$SP_EL0` = current task.
- RKP/KDP driver: `s22/kernel_platform/common/drivers/uh/rkp.c` (`rkp_ro_alloc` per pgd!);
  cmds in `include/linux/rkp.h` (`RKP_ROBUFFER_ALLOC=0x07`, `FREE=0x08`).

## 7. Exploit-side facts (S25U tree, s22 target)

`CVE-2026-43499-S25U/src/targets/s22/target.h` (GDB-verified): `rt_mutex_waiter` 80B (task@0x30,
lock@0x38, pi_tree_entry@0x18, prio@0x40, deadline@0x48); `task_struct` pid@0x5c8, pi_blocked_on@0x898,
usage@0x40, prio@0x84, pi_lock@0x86c, pi_waiters@0x880, pi_top_task@0x890; `file_operations` 288B
(read@0x10, write@0x18, llseek@0x08, ioctl@0x50); configfs buffer page@16/bin_buffer@88;
`ashmem_misc.fops` off `0x026ec728`; `ashmem_fops` off `0x0207f160`; `init_task` off `0x0259c000`;
configfs read=`configfs_read_file` `0x00602060`, write=`configfs_write_bin_file` `0x006029f0` (JT addrs);
mm_struct 960B, order-3 slab.
Prior notes: `PORTING-NOTES-v5.10.md` (Issue #1 fixed: .read must be configfs_read_file;
Issue #2 superseded — the exp32 write path does NOT depend on stale-waiter tree membership).

## 8. IonStackQuest3 (working v5.10 route)

`/home/sarab/v5-kernel/qemu/IonStackQuest3/`: `src/exp32/` (32-bit stage: choreography →
`do_stamp_stack` = `setsockopt(MCAST_JOIN_SOURCE_GROUP, 260B)` loop; consumer = one `sched_setattr`);
`src/api.c::exp_stack_once` (memfd payload, fresh child per attempt); page: fake_lock zeroed, fake_task
detached, no fake_w0; write from stamped waiter's own tree_entry; KASLR via perf_event callchain
sampling (`src/q3slide.c::getkerneltextstart` — no tracefs; worth porting for the real device).

## 9. Why 32-bit is mandatory (verified in b0q source)

- Stamp: `net/ipv6/ipv6_sockglue.c` `do_ipv6_setsockopt` case MCAST_JOIN_SOURCE_GROUP (:883) →
  `do_ipv6_mcast_group_source` (:162, stack `greqs`) → `copy_group_source_from_sockptr` (:139):
  compat branch copies 260B `compat_group_source_req gr32` (`include/net/compat.h:75`, `__aligned(4)`);
  native needs 264B with a 4B hole (`include/uapi/linux/socket.h:16` `void *__align`).
  ⇒ `setsockopt(...,260)` is EINVAL on 64-bit (no copy), exact on compat.
- Waiter: `kernel/futex/core.c:3196` `rt_waiter` on stack; compat entries `futex` (:3795) /
  `futex_time32` (:3991) — same core, different wrappers → geometry is compat-specific.

## 10. THE MEASUREMENT (+0x58)

Live on b0q QEMU (nokaslr), probe = `/tmp/probe32` (source `/home/sarab/v5-kernel/qemu/probe32.c`,
`arm-linux-gnueabi-gcc -static -O2`; comm `probe32`):
- `futex_wait_requeue_pi`: `sub sp,#0x1a0`; waiter at frame sp+0x90 (via `add x2,sp,#0x90` before
  `bl rt_mutex_wait_proxy_lock`) → `rt_waiter = entry_sp − 0x110`.
- `do_ipv6_setsockopt`: `sp -= 0x60+0x280`; compat branch (TIF_32BIT `tbnz w8,#22`) copies 260B at
  `sp+0x168` → `gr32 = entry_sp − 0x178`.
- Captured: futex entry_sp `0xffffffc00b26bd70` → waiter `0xffffffc00b26bc60`;
  setsockopt entry_sp `0xffffffc00b26bd80` → gr32 `0xffffffc00b26bc08`.
- **delta = 0x58** (eureka: 0x34). Deterministic across hits (no kstack randomization).
Payload word map (base = waiter+0x00 → buffer+0x58): +0x00 pc=fake_fops, +0x08 right=0,
+0x10 left=target, +0x18..+0x28 pi_tree=0, +0x30 task=fake_task, +0x38 lock=fake_lock,
+0x40 prio, +0x48 deadline. Stamp window `[gr32, gr32+0x104)` fully contains the 80B waiter.
Caveat: measured via compat futex nr 240 (futex_time32); re-measure if switching to nr 422.

## 11. Guest environment / reproduction

- `run.sh` (cwd) boots `Image` (b0q, nokaslr) `-cpu cortex-a710,sve=off -smp 8 -m 12288` `-s` (gdbstub
  :1234); `debug.sh` attaches gdb; **use hardware breakpoints** (`hbreak`) — gdbstub reads near
  stopped-CPU TLB pages only. SSH `ssh -p 13337 root@localhost` (root). Buildroot rootfs `rootfs.ext2`.
- Guest init: `/etc/init.d/S99cve` (ashmem node from /proc/misc + tracefs mount) — persists in rootfs.
- Push: `scp -P 13337 build/s22-qemu/bin/cve-2026-43499 root@localhost:/tmp/cve-s22`.
- Run: `LD_PRELOAD=/tmp/cve-s22 sh` (console) — or via ssh with output to `/tmp/exp.log`.
- KASLR: QEMU has `nokaslr` (slide 0); if on: slide = `VBAR_EL1 − 0x13800 − 0xffffffc008000000`.
- tracefs IS mounted; the kprobe page-verify still unavailable (by design — proceeds unverified).

## 12. Next steps

1. ~~Fix the CFS-path payload tear~~ — DONE (§4f): post-stamp printf tore the
   payload; fixed by probe-print-first + no syscalls after the last stamp.
   **Device retest pending**: build `make PROJECT=s22 clean preload root-helper`
   (NDK), run as shell, expect no more `rt_mutex_adjust_prio_chain+388` panics.
2. **Fix the pipe phys gate (§4e) + phys read path (§4c) — top priority.**
   Read `src/pipe.c` (gate logic, read64 vs write64 address math); check what `c2k/pipe
   0x0460000000000f82` is (flags/counters vs kmem_cache ptr); correct
   `VMEMMAP_START` to `0xfffffffefde00000` in `src/targets/s22/target.h` and
   document pipe.c's memstart/VMEMMAP cancellation so they aren't "fixed"
   independently later.
3. After phys r/w works: leak_kernel_base cross-check → patch cred/SELinux (watch KDP
   emulation interplay with `prepare_ro_creds`/`security_integrity_current`).
4. If `cfi misc_fops mismatch` ever recurs: hw watchpoint `0xffffffc00a6ec728`, catch the
   walk live; §4b has the full SLUB tracepoint recipe.
5. Watch the RKP pool under the clone spray (`[uh] RKP pool EXHAUSTED` in run 3):
   if it recurs, qemu-src pool sizing/recycling needs another look.
6. Port perf_event KASLR leak (`IonStackQuest3/src/q3slide.c`) to drop tracefs dependency for b0q device.
