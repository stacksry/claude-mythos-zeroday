"""
hack_registry.py

Loads vulnerability definitions from the research/ and fixes/ directories.
Each Hack entry carries structured discovery metadata so the scanner can
check infra, OS, language, framework, and library versions before doing
code-level pattern matching.

Covers all 8 Mythos vulnerability classes:
  1. Memory safety      — OOB read/write, use-after-free, heap corruption, stack overflow
  2. Logic bugs         — auth bypass, KASLR leak, protocol impl gap, crypto verification flaw
  3. Code weaknesses    — missing bounds check, integer overflow, unsafe pointer arithmetic
  4. Web / app          — deserialization RCE, SQL injection, CSRF, account takeover
  5. System / kernel    — NFS RCE, LPE via race condition, hypervisor escape
  6. Firmware           — JIT exploitation, hardware interaction
  7. Cryptography       — weak cipher, missing verification, nonce reuse
  8. Network protocols  — protocol parsing, TLS downgrade, session fixation
"""

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


REPO_ROOT = Path(__file__).parent.parent


@dataclass
class AffectedLibrary:
    """A library/package that exposes the vulnerability when present."""
    name: str                          # e.g. "commons-collections"
    ecosystem: str                     # maven | npm | pypi | go | gem | cargo | nuget | apt
    vulnerable_versions: str           # semver range, e.g. "< 3.2.2" or ">= 4.0, < 4.1"
    safe_version: Optional[str] = None # e.g. "3.2.2"


@dataclass
class Hack:
    id: str                            # e.g. "2026-04-10_ffmpeg-oob-write"
    title: str                         # e.g. "FFmpeg Out-of-Bounds Write"
    severity: str                      # Critical / High / Medium / Low
    language: str                      # c, java, python, javascript, go, ruby, etc.

    # ── Discovery layers ────────────────────────────────────────────────────
    infra_signals: list[str] = field(default_factory=list)
    os_signals: list[str] = field(default_factory=list)
    language_files: list[str] = field(default_factory=list)
    framework_signals: list[str] = field(default_factory=list)
    affected_libraries: list[AffectedLibrary] = field(default_factory=list)
    scan_patterns: list[str] = field(default_factory=list)

    # ── Fix metadata ─────────────────────────────────────────────────────────
    fix_description: str = ""
    research_path: Optional[Path] = None
    fix_path: Optional[Path] = None
    raw_research: str = ""
    raw_fix: str = ""


# ---------------------------------------------------------------------------
# Built-in discovery profiles — all 8 Mythos vulnerability classes
# ---------------------------------------------------------------------------

_PROFILES: dict[str, dict] = {

    # ── Class 1: Memory Safety ───────────────────────────────────────────────
    "oob": {
        "infra_signals": ["Dockerfile", "Makefile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM alpine"],
        "language_files": ["*.c", "*.h", "CMakeLists.txt", "Makefile", "configure.ac"],
        "framework_signals": ["libav", "ffmpeg", "gstreamer", "vlc", "libpng", "libjpeg"],
        "affected_libraries": [
            AffectedLibrary("ffmpeg", "apt", "< 6.1.2", "6.1.2"),
            AffectedLibrary("libavcodec", "apt", "< 6.1.2", "6.1.2"),
            AffectedLibrary("libpng", "apt", "< 1.6.40", "1.6.40"),
        ],
        "scan_patterns": [
            "malloc(width * height)",
            "for (int i = 0; i < num_planes",
            "memcpy(",
            "strcpy(",
            "buf[i] = ",
        ],
    },
    "use_after_free": {
        "infra_signals": ["Dockerfile", "Makefile"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM alpine"],
        "language_files": ["*.c", "*.cpp", "*.h"],
        "framework_signals": ["openssl", "webkit", "linux kernel", "chromium"],
        "affected_libraries": [
            AffectedLibrary("openssl", "apt", "< 3.0.8", "3.0.8"),
            AffectedLibrary("libssl-dev", "apt", "< 3.0.8", "3.0.8"),
        ],
        "scan_patterns": [
            "free(", "kfree(", "delete ", "munmap(",
            "->next", "->prev",  # dangling pointer traversal
        ],
    },
    "stack_overflow": {
        "infra_signals": ["Dockerfile", "Makefile"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c", "*.cpp"],
        "framework_signals": ["nfs", "smb", "rpc", "dbus"],
        "affected_libraries": [
            AffectedLibrary("libnfs", "apt", "< 5.0.3", "5.0.3"),
            AffectedLibrary("samba", "apt", "< 4.18.0", "4.18.0"),
        ],
        "scan_patterns": [
            "char buf[", "int buf[", "alloca(",
            "gets(", "scanf(\"%s\"",
            "sprintf(buf,",
        ],
    },
    "heap_corruption": {
        "infra_signals": ["Dockerfile", "Makefile"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c", "*.cpp"],
        "framework_signals": ["openjdk", "jvm", "v8", "spidermonkey"],
        "affected_libraries": [
            AffectedLibrary("jdk", "apt", "< 21.0.3", "21.0.3"),
        ],
        "scan_patterns": [
            "realloc(", "malloc(", "calloc(",
            "UNSAFE.allocateMemory", "sun.misc.Unsafe",
        ],
    },

    # ── Class 2: Logic Bugs ──────────────────────────────────────────────────
    "auth_bypass": {
        "infra_signals": ["Dockerfile", "docker-compose.yml", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM node", "FROM python"],
        "language_files": ["*.java", "*.py", "*.js", "*.ts", "*.go", "*.rb"],
        "framework_signals": ["spring-security", "passport", "devise", "oauth2", "jwt"],
        "affected_libraries": [
            AffectedLibrary("spring-security", "maven", "< 6.1.2", "6.1.2"),
            AffectedLibrary("jsonwebtoken", "npm", "< 9.0.0", "9.0.0"),
            AffectedLibrary("pyjwt", "pypi", "< 2.4.0", "2.4.0"),
        ],
        "scan_patterns": [
            "verify(token", "decode(token",
            "if (token == null)", "if (!authenticated)",
            'algorithm: "none"', "alg: 'none'",
            "permitAll()", "antMatchers(\"/**\")",
        ],
    },
    "kaslr_leak": {
        "infra_signals": ["Makefile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c", "*.h"],
        "framework_signals": ["linux kernel", "kvm", "xen"],
        "affected_libraries": [],
        "scan_patterns": [
            "printk(", "copy_to_user(",
            "KERN_INFO", "seq_printf(",
            "proc_create(", "/proc/",
        ],
    },
    "crypto_verification": {
        "infra_signals": ["Dockerfile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM alpine", "FROM node"],
        "language_files": ["*.java", "*.py", "*.js", "*.go"],
        "framework_signals": ["openssl", "bouncycastle", "cryptography", "nacl"],
        "affected_libraries": [
            AffectedLibrary("bouncy-castle-crypto", "maven", "< 1.70", "1.70"),
            AffectedLibrary("cryptography", "pypi", "< 41.0.0", "41.0.0"),
            AffectedLibrary("node-forge", "npm", "< 1.3.1", "1.3.1"),
        ],
        "scan_patterns": [
            "verify(", "checkSignature(",
            "digest.equals(", "Arrays.equals(hmac",
            "MessageDigest.isEqual(", "hmac.verify(",
        ],
    },
    "protocol_impl_gap": {
        "infra_signals": ["Dockerfile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM alpine"],
        "language_files": ["*.c", "*.go", "*.java", "*.py"],
        "framework_signals": ["nfs", "smb", "ftp", "http", "grpc", "thrift"],
        "affected_libraries": [
            AffectedLibrary("grpc", "go", "< 1.55.0", "1.55.0"),
            AffectedLibrary("thrift", "maven", "< 0.17.0", "0.17.0"),
        ],
        "scan_patterns": [
            "state == ", "if (state !=", "switch (state)",
            "recv(", "read(fd,", "fgets(",
            "parseHeader(", "readPacket(",
        ],
    },

    # ── Class 3: Code Weaknesses ─────────────────────────────────────────────
    "integer_overflow": {
        "infra_signals": ["Dockerfile", "Makefile"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c", "*.cpp", "*.java"],
        "framework_signals": ["ffmpeg", "imagemagick", "openssl"],
        "affected_libraries": [
            AffectedLibrary("imagemagick", "apt", "< 7.1.1-12", "7.1.1-12"),
        ],
        "scan_patterns": [
            "width * height", "size * count", "len << ",
            "(int)(", "(short)(", "(byte)(",
            "Math.toIntExact(", "Math.multiplyExact(",
        ],
    },
    "missing_bounds_check": {
        "infra_signals": ["Dockerfile", "Makefile"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c", "*.cpp"],
        "framework_signals": ["libxml2", "expat", "zlib", "libarchive"],
        "affected_libraries": [
            AffectedLibrary("libxml2", "apt", "< 2.12.0", "2.12.0"),
            AffectedLibrary("expat", "apt", "< 2.5.0", "2.5.0"),
            AffectedLibrary("zlib", "apt", "< 1.3.1", "1.3.1"),
        ],
        "scan_patterns": [
            "buf[", "array[", "ptr +",
            "if (len > sizeof", "if (size >",
            "assert(", "ASSERT(",
        ],
    },

    # ── Class 4: Web / Application ───────────────────────────────────────────
    "deserialization": {
        "infra_signals": ["Dockerfile", "docker-compose.yml", ".github/workflows/*.yml"],
        "os_signals": ["FROM openjdk", "FROM eclipse-temurin", "FROM amazoncorretto"],
        "language_files": ["pom.xml", "build.gradle", "*.java"],
        "framework_signals": ["spring-boot", "struts", "jboss", "weblogic", "jenkins"],
        "affected_libraries": [
            AffectedLibrary("commons-collections", "maven", "< 3.2.2", "3.2.2"),
            AffectedLibrary("commons-collections4", "maven", "< 4.1", "4.1"),
            AffectedLibrary("spring-core", "maven", ">= 4.0, < 5.3.18", "5.3.18"),
            AffectedLibrary("jackson-databind", "maven", "< 2.14.0", "2.14.0"),
            AffectedLibrary("xstream", "maven", "< 1.4.19", "1.4.19"),
            AffectedLibrary("log4j-core", "maven", ">= 2.0, < 2.17.1", "2.17.1"),
        ],
        "scan_patterns": [
            "new ObjectInputStream(", "readObject()", ".readObject()",
            "XMLDecoder(", "XStream().fromXML(",
            "JSON.parseObject(", "mapper.readValue(",
        ],
    },
    "sql_injection": {
        "infra_signals": ["Dockerfile", "docker-compose.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM python", "FROM node"],
        "language_files": ["*.py", "*.java", "*.php", "*.js", "*.rb"],
        "framework_signals": ["django", "flask", "spring", "rails", "express", "laravel"],
        "affected_libraries": [
            AffectedLibrary("django", "pypi", "< 4.2.4", "4.2.4"),
            AffectedLibrary("sequelize", "npm", "< 6.33.0", "6.33.0"),
            AffectedLibrary("activerecord", "gem", "< 7.0.7", "7.0.7"),
        ],
        "scan_patterns": [
            'f"SELECT', 'f"INSERT', 'f"UPDATE', 'f"DELETE',
            "\"SELECT \" +", "\"WHERE \" +",
            "execute(query,", "cursor.execute(f",
            "where(\"id = #{", "find_by_sql(",
        ],
    },
    "csrf": {
        "infra_signals": ["Dockerfile", "docker-compose.yml"],
        "os_signals": ["FROM node", "FROM python", "FROM php"],
        "language_files": ["*.js", "*.ts", "*.py", "*.php"],
        "framework_signals": ["express", "django", "laravel", "rails", "flask"],
        "affected_libraries": [
            AffectedLibrary("express", "npm", "< 4.18.2", "4.18.2"),
        ],
        "scan_patterns": [
            "csrf: false", "csrfProtection = false",
            "CSRF_COOKIE_SECURE = False", "@csrf_exempt",
            "csrf_token", "X-CSRF-Token",
        ],
    },

    # ── Class 5: System / Kernel ─────────────────────────────────────────────
    "nfs_rce": {
        "infra_signals": ["Makefile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c"],
        "framework_signals": ["nfs-kernel-server", "nfsd", "sunrpc"],
        "affected_libraries": [
            AffectedLibrary("nfs-kernel-server", "apt", "< 2.6.4", "2.6.4"),
        ],
        "scan_patterns": [
            "nfsd_", "svc_process(", "rpc_call(",
            "xdr_decode", "xdr_encode",
            "copy_from_user(", "copy_to_user(",
        ],
    },
    "lpe_race_condition": {
        "infra_signals": ["Makefile"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c"],
        "framework_signals": ["linux kernel", "systemd", "dbus"],
        "affected_libraries": [],
        "scan_patterns": [
            "mutex_lock(", "spin_lock(", "rcu_read_lock(",
            "current->cred", "prepare_creds(",
            "commit_creds(", "set_current_user(",
        ],
    },
    "hypervisor_escape": {
        "infra_signals": ["Makefile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c"],
        "framework_signals": ["qemu", "kvm", "xen", "virtualbox"],
        "affected_libraries": [
            AffectedLibrary("qemu", "apt", "< 8.1.0", "8.1.0"),
        ],
        "scan_patterns": [
            "MMIO", "mmio_write", "ioport_write",
            "pci_config_write", "virtio_",
            "kvm_vcpu_ioctl(", "kvm_run",
        ],
    },

    # ── Class 6: Firmware ────────────────────────────────────────────────────
    "jit_exploitation": {
        "infra_signals": ["Dockerfile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian"],
        "language_files": ["*.c", "*.cpp", "*.js"],
        "framework_signals": ["v8", "spidermonkey", "javascriptcore", "llvm"],
        "affected_libraries": [],
        "scan_patterns": [
            "JIT_COMPILE", "jit_code(", "emit_jit(",
            "mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC",
            "mprotect(", "VirtualAlloc(",
        ],
    },

    # ── Class 7: Cryptography ────────────────────────────────────────────────
    "weak_crypto": {
        "infra_signals": ["Dockerfile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM node", "FROM python"],
        "language_files": ["*.py", "*.java", "*.js", "*.go"],
        "framework_signals": ["openssl", "bouncycastle", "cryptography", "pycryptodome"],
        "affected_libraries": [
            AffectedLibrary("pycryptodome", "pypi", "< 3.18.0", "3.18.0"),
            AffectedLibrary("bouncy-castle-crypto", "maven", "< 1.73", "1.73"),
        ],
        "scan_patterns": [
            '"MD5"', '"SHA1"', '"SHA-1"', '"DES"', '"RC4"',
            "Cipher.getInstance(\"AES/ECB",
            "new SecretKeySpec(key, \"DES\")",
            "hashlib.md5(", "hashlib.sha1(",
        ],
    },

    # ── Class 8: Network Protocols ───────────────────────────────────────────
    "tls_downgrade": {
        "infra_signals": ["Dockerfile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM alpine"],
        "language_files": ["*.c", "*.py", "*.java", "*.go"],
        "framework_signals": ["openssl", "gnutls", "boringssl", "mbedtls"],
        "affected_libraries": [
            AffectedLibrary("openssl", "apt", "< 3.0.8", "3.0.8"),
            AffectedLibrary("openssl", "pypi", "< 23.0.0", "23.0.0"),
        ],
        "scan_patterns": [
            "SSLv3", "TLSv1.0", "TLSv1.1",
            "ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_TLSv1",
            "SSL_CTX_set_min_proto_version",
            "verify=False", "check_hostname=False",
        ],
    },
}


def _match_profile(research_text: str, stem: str) -> str:
    """Return the best matching profile key for a research doc."""
    text = research_text.lower() + stem.lower()

    # Memory safety
    if "use-after-free" in text or "use after free" in text:
        return "use_after_free"
    if "stack overflow" in text or "stack buffer" in text:
        return "stack_overflow"
    if "heap corruption" in text or "heap overflow" in text:
        return "heap_corruption"
    if "out-of-bounds" in text or "oob" in text or "ffmpeg" in text:
        return "oob"

    # Logic bugs
    if "auth bypass" in text or "authentication bypass" in text:
        return "auth_bypass"
    if "kaslr" in text or "kernel address" in text:
        return "kaslr_leak"
    if "crypto verification" in text or "signature verif" in text:
        return "crypto_verification"
    if "protocol" in text and ("gap" in text or "state" in text):
        return "protocol_impl_gap"

    # Code weaknesses
    if "integer overflow" in text or "integer wrap" in text:
        return "integer_overflow"
    if "bounds check" in text or "missing check" in text:
        return "missing_bounds_check"

    # Web / App
    if "deserialization" in text or "readobject" in text:
        return "deserialization"
    if "sql injection" in text or "sqli" in text:
        return "sql_injection"
    if "csrf" in text or "cross-site request" in text:
        return "csrf"

    # System / Kernel
    if "nfs" in text and ("rce" in text or "remote code" in text):
        return "nfs_rce"
    if "race condition" in text and ("lpe" in text or "privilege" in text):
        return "lpe_race_condition"
    if "hypervisor" in text or "vm escape" in text or "qemu" in text:
        return "hypervisor_escape"

    # Firmware
    if "jit" in text:
        return "jit_exploitation"

    # Crypto
    if "weak cipher" in text or "weak crypto" in text or "md5" in text or "sha1" in text:
        return "weak_crypto"

    # Network
    if "tls" in text and ("downgrade" in text or "sslv3" in text):
        return "tls_downgrade"

    return ""


def _extract_field(text: str, key: str) -> str:
    for pattern in [rf"\*\*{key}:\*\*\s*(.+)", rf"{key}:\s*(.+)"]:
        m = re.search(pattern, text)
        if m:
            return m.group(1).strip()
    return ""


def _infer_language(text: str, filename: str) -> str:
    t = text.lower() + filename.lower()
    if "java" in t or "jvm" in t:
        return "java"
    if ".c " in t or "c/c++" in t or "ffmpeg" in t or "kernel" in t:
        return "c"
    if "python" in t or "django" in t or "flask" in t:
        return "python"
    if "javascript" in t or "node" in t or "npm" in t or "typescript" in t:
        return "javascript"
    if "go " in t or "golang" in t:
        return "go"
    if "ruby" in t or "rails" in t or "gem" in t:
        return "ruby"
    if "rust" in t or "cargo" in t:
        return "rust"
    return "unknown"


def _extract_fix_description(raw_fix: str) -> str:
    m = re.search(r"## The Fix.*?\n(.*?)##", raw_fix, re.DOTALL)
    return m.group(1).strip()[:500] if m else ""


def load_hacks() -> list[Hack]:
    """
    Scan research/ and fixes/ directories.
    Returns Hack objects with full structured discovery metadata.
    """
    research_dir = REPO_ROOT / "research"
    fixes_dir = REPO_ROOT / "fixes"
    hacks = []

    if not research_dir.exists():
        return []

    for research_file in sorted(research_dir.glob("*.md")):
        stem = research_file.stem
        raw_research = research_file.read_text()

        # Find matching fix doc
        fix_file = None
        if fixes_dir.exists():
            for candidate in fixes_dir.glob("*.md"):
                if stem.replace("_poc", "") in candidate.stem:
                    fix_file = candidate
                    break
        raw_fix = fix_file.read_text() if fix_file else ""

        # Core fields
        severity = _extract_field(raw_research, "Severity")
        language = _infer_language(raw_research, stem)
        title = stem.split("_", 1)[-1].replace("-", " ").title()
        if ":" not in title:
            title = f"[{language.upper()}] {title}"

        # Structured discovery from profile
        profile_key = _match_profile(raw_research, stem)
        profile = _PROFILES.get(profile_key, {})

        hacks.append(Hack(
            id=stem,
            title=title,
            severity=severity or "Unknown",
            language=language,
            infra_signals=profile.get("infra_signals", ["Dockerfile", ".github/workflows/*.yml"]),
            os_signals=profile.get("os_signals", []),
            language_files=profile.get("language_files", [f"*.{language}"]),
            framework_signals=profile.get("framework_signals", []),
            affected_libraries=profile.get("affected_libraries", []),
            scan_patterns=profile.get("scan_patterns", []),
            fix_description=_extract_fix_description(raw_fix) or "See fix doc.",
            research_path=research_file,
            fix_path=fix_file,
            raw_research=raw_research,
            raw_fix=raw_fix,
        ))

    return hacks


if __name__ == "__main__":
    for hack in load_hacks():
        print(f"[{hack.severity}] {hack.title}")
        print(f"  Language   : {hack.language}")
        print(f"  Infra      : {hack.infra_signals}")
        print(f"  OS         : {hack.os_signals}")
        print(f"  Lang files : {hack.language_files}")
        print(f"  Frameworks : {hack.framework_signals}")
        print(f"  Libraries  : {[(l.name, l.vulnerable_versions) for l in hack.affected_libraries]}")
        print(f"  Patterns   : {hack.scan_patterns}")
        print()
