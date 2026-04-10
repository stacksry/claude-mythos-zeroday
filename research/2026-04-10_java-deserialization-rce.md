# Vulnerability Research: Java Unsafe Deserialization → RCE

**Date:** 2026-04-10
**Researcher:** stacksry
**Severity:** Critical
**Status:** Patched (training exercise)
**Glasswing relevance:** Claude Mythos found a guest-to-host memory corruption bug in a
memory-safe VM monitor — proving memory-safe languages still have exploitable logic bugs.
Java deserialization is the canonical example of this class.

---

## Summary

Java's `ObjectInputStream` deserializes arbitrary objects from a byte stream with no type
validation by default. An attacker who controls the input stream can send a crafted
serialized payload that, when deserialized, executes arbitrary code — regardless of the
fact that Java is a "memory-safe" language. The JVM enforces memory safety; it does not
enforce *semantic* safety.

This is why Glasswing's finding matters: **logic bugs don't care about your type system.**

---

## Affected Pattern

Any Java code that does:
```java
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
Object obj = ois.readObject();   // DANGER: no type filter
```

Common victims: Apache Commons Collections, Spring, JBoss, WebLogic, Jenkins.

---

## Root Cause

Java's serialization protocol restores object graphs by calling each class's
`readObject()` method during deserialization. Attackers chain classes already on the
classpath (called "gadget chains") whose `readObject()` methods, when called in sequence,
produce a Runtime.exec() call. No custom code needed — only classes already in the JVM.

---

## Attack Vector

1. Attacker identifies a Java endpoint that accepts serialized objects
   (RMI, JMX, custom protocol, HTTP body with `application/x-java-serialized-object`)
2. Attacker generates a gadget chain payload (e.g. via ysoserial)
3. Payload is sent to the endpoint
4. Server deserializes it → gadget chain fires → RCE

---

## Impact

- **Confidentiality:** Critical (full server access)
- **Integrity:** Critical
- **Availability:** Critical
- **CVSS:** 9.8 (Critical) — unauthenticated RCE in typical deployments

---

## Why This Is a Glasswing-Class Bug

- The JVM enforces memory safety — no buffer overflows possible in Java
- But the *logic* of `readObject()` is semantically unsafe
- Static analyzers flag `readObject()` calls but miss gadget chain reachability
- Mythos-style reasoning traces the full object graph to find exploitable chains

---

## References

- [CVE-2015-4852 — Apache Commons Collections RCE](https://nvd.nist.gov/vuln/detail/CVE-2015-4852)
- [Glasswing memory-safe VM monitor finding](https://www.anthropic.com/glasswing)
- [NxCode Glasswing deep-dive](https://www.nxcode.io/resources/news/project-glasswing-claude-mythos-zero-day-ai-cybersecurity-2026)
