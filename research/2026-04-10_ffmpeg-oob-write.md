# Vulnerability Research: FFmpeg Out-of-Bounds Write (Glasswing Training Exercise)

**Date:** 2026-04-10
**Researcher:** stacksry
**Severity:** High
**Status:** Patched (upstream) — Training exercise based on real Glasswing finding
**Reference:** Project Glasswing / Claude Mythos Preview discovery

---

## Summary

Claude Mythos Preview discovered a 16-year-old out-of-bounds write in FFmpeg — a media
encoding/decoding library used by nearly every video pipeline on the internet. Automated
fuzz testing had executed the vulnerable code path ~5 million times without catching it.

This exercise recreates the *class* of bug (not the exact line) so you can learn to:
- recognize OOB write patterns in C
- reproduce with AddressSanitizer (ASan)
- write a correct bounds-checked fix
- document mitigations

---

## Vulnerability Class: Out-of-Bounds Write

### Root Cause

A buffer is allocated with a size calculated from media metadata (e.g. width × height).
A downstream function writes into that buffer using an index derived from a *separate*
metadata field that is never validated against the buffer size. When the two fields are
crafted to be inconsistent, the write lands past the end of the allocation.

### Attack Vector

- Attacker crafts a malicious media file (e.g. .mp4, .mkv, .avi)
- File is processed by a vulnerable FFmpeg version (or any app embedding libavcodec)
- The inconsistent metadata triggers the OOB write
- Depending on heap layout: crash (DoS), data corruption, or code execution

### Impact

- **Confidentiality:** Medium (heap data disclosure possible)
- **Integrity:** High (memory corruption)
- **Availability:** High (crash / DoS)
- **CVSS estimate:** 7.8 (High)

### Why Fuzzers Missed It

The OOB write only triggers when two separate metadata fields (allocated size vs. write
index) are **inconsistent in a specific way**. Most fuzz inputs randomize fields
independently and happen to keep them consistent. Mythos reasoned about the *semantic
relationship* between the two fields — something coverage-guided fuzzers cannot do.

---

## References

- [Project Glasswing](https://www.anthropic.com/glasswing)
- [Hacker News writeup](https://thehackernews.com/2026/04/anthropics-claude-mythos-finds.html)
- [SC Media — Mythos findings](https://www.scworld.com/news/anthropic-claude-mythos-preview-finds-thousands-of-vulnerabilities-in-weeks)
- [News9 — FFmpeg 16-year bug](https://www.news9live.com/technology/artificial-intelligence/project-glasswing-ai-decade-old-bugs-openbsd-ffmpeg-2953574)
