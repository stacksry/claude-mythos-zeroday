# Mitigation: FFmpeg-Style Out-of-Bounds Write

**Date:** 2026-04-10
**Related Research:** `research/2026-04-10_ffmpeg-oob-write.md`
**Status:** Applied (upstream patched)

---

## Short-Term Mitigation

1. **Compiler flags** — build FFmpeg (and embedding apps) with:
   ```
   -fsanitize=address          # catch OOB at runtime (dev/staging)
   -D_FORTIFY_SOURCE=2         # glibc buffer overflow detection
   -fstack-protector-strong    # stack canaries
   ```

2. **Sandbox / seccomp** — run FFmpeg in a restricted sandbox so a triggered
   corruption cannot pivot to full process control:
   ```bash
   # Linux: drop syscalls not needed for decoding
   seccomp-tools dump ffmpeg -i input.mp4
   ```

3. **Input validation at ingest** — reject media files with metadata fields
   that are implausible (e.g. `num_planes > width * height`) before they reach
   the decoder.

---

## Long-Term Fix

Validate all metadata-derived indices against their target buffer size
**before** allocation or any write. See `tools/fixed_decoder.c` for the
reference implementation.

Pattern to enforce in code review:
```c
/* BEFORE every loop that writes into a buffer */
if (index_bound > buffer_size) {
    return AVERROR_INVALIDDATA;  /* FFmpeg convention */
}
```

---

## Verification Steps

1. Build with ASan: `clang -fsanitize=address -g -o test tools/vulnerable_decoder.c`
2. Confirm crash: `./test 10 10 999` → ASan heap-buffer-overflow
3. Apply fix (implement `decode_frame_fixed`)
4. Rebuild and re-run: `./test 10 10 999` → graceful rejection, no crash

---

## Rollback Plan

The fix is additive (a bounds check before existing logic). To revert: remove
the `if (num_planes > buf_size)` guard and rebuild.
