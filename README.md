# pam-ed25529

**pam-ed25529** is a PAM module that implements a human-readable challenge–response login mechanism. It is primarily intended for situations where the transport layer can be assumed to be secure—such as a serial connection, local console, or remote control via tools like TeamViewer—and where authentication is traditionally password-based.

Instead of using a static password, this module generates a unique login prompt based on a server-generated challenge. The user must respond with a digital signature, providing a stronger, per-session authentication method.

---

## 🔐 Why Ed25519?

This module currently supports only **Ed25519** keys. The reasons for this are:

- **Compact challenge size** (32 bytes)
- **Small signature size** (64 bytes)
- **Fast and secure** elliptic-curve cryptography
- Ideal for human-in-the-loop workflows where visual inspection or typing is involved

---

## 🔡 Challenge & Response Encoding

Both the **challenge** and the **response** are encoded using **base85**:

- Keeps strings **short**
- Ensures **ASCII-only** output (safe for virtually any transport layer)
- Avoids issues with line breaks, special characters, or encodings

---

## 🛠️ Usage

The module works like a typical PAM authentication plugin:

1. The server generates a 32-byte random challenge.
2. This challenge is shown to the user, encoded in base85.
3. The user signs the challenge using their Ed25519 private key.
4. The user enters the base85-encoded signature as their "password".
5. The PAM module verifies the signature against the authorized public key.

---

## 🔌 Integration

You can integrate `pam-ed25529` into any PAM-based service. For example:

### `/etc/pam.d/login`

For login, the module will check if the signature matches $(HOME)/.ssh/id_ed25519.pub.
