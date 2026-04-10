# Fix: Java Unsafe Deserialization → RCE

**Date:** 2026-04-10
**Related Research:** `research/2026-04-10_java-deserialization-rce.md`
**Status:** Verified

---

## The Fix (JEP 290 Serialization Filter — JDK 9+)

```java
ObjectInputStream ois = new ObjectInputStream(untrustedStream);

// Install whitelist filter BEFORE readObject()
ois.setObjectInputFilter(filterInfo -> {
    Class<?> cls = filterInfo.serialClass();
    if (cls == null) return ObjectInputFilter.Status.ALLOWED;

    // Only allow your known-safe DTO classes
    if (cls == YourSafeDTO.class) {
        return ObjectInputFilter.Status.ALLOWED;
    }

    return ObjectInputFilter.Status.REJECTED;  // block everything else
});

Object obj = ois.readObject();  // safe — gadget chains are blocked
```

---

## Alternative Fixes (Defense in Depth)

### 1. Avoid Java serialization entirely
Switch to JSON, Protobuf, or Avro for network data. No ObjectInputStream = no attack surface.

```java
// Instead of ObjectInputStream, use Jackson:
ObjectMapper mapper = new ObjectMapper();
YourDTO dto = mapper.readValue(inputStream, YourDTO.class);
```

### 2. Global JVM filter (JDK 17+)
Set a process-wide filter in `$JAVA_HOME/conf/security/java.security`:
```
jdk.serialFilter=com.yourapp.dto.*;java.base/**;!*
```

### 3. Use a look-ahead filter library
[SerialKiller](https://github.com/ikkisoft/SerialKiller) or Apache Commons IO's
`ValidatingObjectInputStream` for older JDKs:
```java
ValidatingObjectInputStream vois = new ValidatingObjectInputStream(inputStream);
vois.accept(YourSafeDTO.class);       // whitelist
vois.reject("org.apache.commons.*"); // explicit blacklist
Object obj = vois.readObject();
```

---

## Code Review Checklist

- [ ] Search for `ObjectInputStream` in codebase: `grep -r "ObjectInputStream" src/`
- [ ] Every `new ObjectInputStream(...)` must have `setObjectInputFilter()` before `readObject()`
- [ ] DTOs that get serialized must NOT have side-effectful `readObject()` overrides
- [ ] Prefer JSON/Protobuf over Java serialization for any network-facing data

---

## Verification

```bash
cd tools/java/
javac SafeServer.java SafeClient.java
java SafeServer &
java SafeClient          # should succeed
java AttackClient        # should be blocked by filter
```
