# Wipher

Lightweight end-to-end encryption library for Java 21+.

Wipher implements a protocol similar to what modern messengers (Signal, WhatsApp) use under the hood — but as a simple, embeddable Java API with zero external dependencies.

---

## What problem does this solve?

Imagine Alice wants to send Bob a secret message through a server.
The server should **deliver** the message but **never be able to read it**.

```
Alice ──[encrypted]──► Server ──[encrypted]──► Bob
                         │
                    can't read ✗
```

This is called **end-to-end encryption (E2E)** — only the sender and receiver can read the content. The server, the network, anyone who intercepts traffic — sees only meaningless ciphertext.

Wipher provides the building blocks to make this work.

---

## How it works (step by step)

### Step 1 — Each side generates a key pair

When Alice installs the app, her device generates an **X25519 key pair**:

- **Private key** — stays on her device forever, never transmitted
- **Public key** — safe to share with anyone (like a phone number)

```java
var alice = Wipher.create();
var alicePublicKey = alice.getPublicKey(); // safe to send anywhere
```

The private key is just a random 32-byte number. The public key is mathematically derived from it, but you **cannot** reverse-compute the private key from the public one.

### Step 2 — Key exchange (Diffie-Hellman)

Alice and Bob exchange **public keys** through the server. The server sees both public keys — that's fine, they're useless without the private keys.

```java
// Alice knows Bob's public key (received from server)
alice.establishSession("bob", bobPublicKey);

// Bob knows Alice's public key (received from server)
bob.establishSession("alice", alicePublicKey);
```

Behind the scenes, each side computes a **shared secret** using their own private key and the other's public key:

```
Alice computes:  SharedSecret = DH(alice_private, bob_public)
Bob computes:    SharedSecret = DH(bob_private, alice_public)

Both get the SAME result — without ever transmitting it.
```

This is the magic of Diffie-Hellman: two people arrive at an identical secret number by combining their private data with the other's public data. An eavesdropper who sees both public keys **cannot** compute this secret — it's the discrete logarithm problem, which has no known efficient solution.

### Step 3 — Key derivation (HKDF)

The raw DH shared secret is not directly suitable as an encryption key. We pass it through **HKDF** (HMAC-based Key Derivation Function, RFC 5869) to produce a clean, uniform 256-bit AES key:

```
DH shared secret (32 bytes, non-uniform)
         │
         ▼
   HKDF-SHA256
         │
         ▼
AES-256 key (32 bytes, uniform)
```

Think of it like refining crude oil into gasoline — the raw material is valuable but needs processing before use.

### Step 4 — Encryption (AES-256-GCM)

Now both sides have the same AES key. Every message is encrypted with **AES-256-GCM**:

```java
// Alice encrypts
var encrypted = alice.encrypt("bob", "Hello Bob!");

// Bob decrypts
String text = bob.decrypt("alice", encrypted);
// → "Hello Bob!"
```

**GCM** (Galois/Counter Mode) provides two things at once:
- **Confidentiality** — the message is unreadable without the key
- **Integrity** — if anyone tampers with even a single bit, decryption fails with an error (authentication tag mismatch)

Each message gets a unique random **nonce** (12 bytes), so encrypting the same text twice produces completely different ciphertext.

### What the server sees

```
Alice sends:  MSG a4Bf9x2Kp7...QmR8w==
Server sees:  MSG a4Bf9x2Kp7...QmR8w==   ← meaningless bytes
Bob receives: MSG a4Bf9x2Kp7...QmR8w==
Bob decrypts: "Hello Bob!"               ← only Bob can read
```

---

## Group messaging

Groups are harder. You can't just do DH between 50 people. Wipher uses the **Sender Keys** model (same as Signal):

### How it works

Each group member generates a **sender key** — a random AES key used to encrypt their messages:

```
Alice's sender key:  [random 32 bytes]
Bob's sender key:    [random 32 bytes]
Katya's sender key:  [random 32 bytes]
```

Each member distributes their sender key to all others via **pairwise E2E sessions** (the 1-on-1 encryption described above):

```
Alice → Bob:   encrypt_e2e(alice_bob_session, alice_sender_key)
Alice → Katya: encrypt_e2e(alice_katya_session, alice_sender_key)
```

The server relays these encrypted key blobs but cannot read them.

After setup, everyone knows everyone's sender key:

```java
alice.createGroup("team");
alice.addGroupMember("team", "bob", bobSenderKey);
alice.addGroupMember("team", "katya", katyaSenderKey);
```

When Alice sends a message, she encrypts it **once** with her sender key:

```java
var msg = alice.encryptGroup("team", "Hello team!");
// Server broadcasts this single ciphertext to all members
```

Bob and Katya both know Alice's sender key, so both can decrypt.

### When someone leaves

If Katya is removed, her sender key is compromised (she still has everyone's old keys). Solution: **key rotation**.

```java
byte[] newKey = alice.removeGroupMember("team", "katya");
// Alice generates a new sender key and sends it to remaining members
// Katya has the old key — useless for new messages
```

---

## Why not just use RSA?

RSA is **asymmetric** encryption — public key encrypts, private key decrypts. It works, but:

| | RSA | DH + AES (Wipher) |
|---|---|---|
| Speed | ~0.001 GB/s | ~4 GB/s |
| Message size limit | ~200 bytes per operation | Unlimited |
| Forward secrecy | No | Yes (with key rotation) |
| Use case | Encrypting small data (keys, signatures) | Encrypting everything |

RSA is 4000x slower and can only encrypt tiny chunks. In practice, even RSA-based systems use RSA only to exchange an AES key, then switch to AES for actual data — which is essentially what Wipher does, but with DH instead of RSA (faster, smaller keys, same security).

---

## Why not just use TLS?

TLS protects data **in transit** (client ↔ server). But the server still sees plaintext:

```
TLS:     Alice ──[encrypted]──► Server (decrypts, reads, re-encrypts) ──[encrypted]──► Bob
Wipher:  Alice ──[encrypted]──► Server (can't decrypt) ──[encrypted]──► Bob
```

TLS trusts the server. Wipher doesn't trust anyone except the endpoints.

---

## Can the encryption be broken?

### By brute force?

AES-256 has 2^256 possible keys. If you tried **one trillion keys per second**, it would take longer than the age of the universe — by a factor of 10^50. The energy required to count to 2^256 exceeds the total energy output of the Sun over its lifetime.

### By math?

No known mathematical attack breaks AES-256 or X25519 significantly faster than brute force. This could theoretically change with new mathematical discoveries, but as of today, these are considered secure by every major cryptographic institution (NIST, NSA, GCHQ).

### By quantum computers?

X25519 (elliptic curve DH) would be vulnerable to a sufficiently powerful quantum computer running Shor's algorithm. AES-256 remains safe (Grover's algorithm only halves the effective key length: 256 → 128 bits, still infeasible). Post-quantum key exchange algorithms (Kyber/ML-KEM) exist but are not yet implemented in Wipher.

### By stealing the device?

Yes. If someone has physical access to the device and can extract the private key from memory — game over. Encryption protects data **in transit**, not at rest on a compromised device. Use device encryption (FileVault, BitLocker) and secure enclaves for key storage in production.

---

## API Reference

### Quick start

```java
// Create instances (each represents a device)
var alice = Wipher.create();
var bob = Wipher.create();

// Exchange public keys (through any channel)
alice.establishSession("bob", bob.getPublicKey());
bob.establishSession("alice", alice.getPublicKey());

// Encrypt & decrypt
var encrypted = alice.encrypt("bob", "Secret message");
String decrypted = bob.decrypt("alice", encrypted);
```

### Send files

```java
byte[] fileBytes = Files.readAllBytes(Path.of("document.pdf"));
var encryptedFile = alice.encrypt("bob", fileBytes);

// Bob decrypts
byte[] decryptedFile = bob.decryptBytes("alice", encryptedFile);
```

### Group chat

```java
// Setup
alice.createGroup("project");
bob.createGroup("project");

// Exchange sender keys (via pairwise E2E)
alice.addGroupMember("project", "bob", bob.getGroupSenderKey("project"));
bob.addGroupMember("project", "alice", alice.getGroupSenderKey("project"));

// Broadcast
var msg = alice.encryptGroup("project", "Hello team!");
bob.decryptGroup("project", "alice", msg); // → "Hello team!"
```

### Streaming encryption

For large files (videos, archives, backups) loading everything into memory is not an option.
Wipher splits data into 64KB chunks, each independently encrypted with its own nonce and GCM auth tag.
Memory usage stays constant regardless of file size.

```java
// Alice encrypts a 2 GB video — only 64 KB in memory at a time
InputStream encrypted = alice.encryptStream("bob",
        new FileInputStream("movie.mkv"));

// Bob decrypts — also streaming, never loads full file
InputStream decrypted = bob.decryptStream("alice", encrypted);
Files.copy(decrypted, Path.of("movie-decrypted.mkv"));
```

Wire format (per chunk):
```
[4 bytes: size] [12 bytes: nonce] [size+16 bytes: ciphertext + GCM tag]
[4 bytes: size] [12 bytes: nonce] [size+16 bytes: ciphertext + GCM tag]
...
[4 bytes: 0x00] — end of stream
```

Each chunk is tamper-proof — if a single bit is modified, decryption fails immediately at that chunk without processing the rest.

Works for groups too:

```java
// Alice broadcasts a file to the group
InputStream encrypted = alice.encryptGroupStream("team",
        new FileInputStream("report.pdf"));

// Bob decrypts
InputStream decrypted = bob.decryptGroupStream("team", "alice", encrypted);
```

Custom chunk size for fine-tuning throughput vs. memory:

```java
// 1 KB chunks (low memory, more overhead)
WipherEncryptingStream.wrap(key, inputStream, 1024);

// 1 MB chunks (more memory, less overhead)
WipherEncryptingStream.wrap(key, inputStream, 1024 * 1024);
```

### Custom key storage

```java
// Implement WipherKeyStore for persistent storage
var wipher = Wipher.create(new MyDatabaseKeyStore());
```

---

## Requirements

- Java 21+
- No external dependencies (uses `java.security` and `javax.crypto`)
