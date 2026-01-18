## HellCryptor 💀🔥

**The ultimate military-grade, self-destructing file encryptor** — if you make one typo, your file is nuked **50 times** over, forever.

---

## ⚠️ WARNING

* **Only test on copies.** One wrong passphrase attempt = permanent destruction of the encrypted file.
* This tool is designed for **extreme security scenarios** — think like CIA+FBI+CID+RAW+ISIS+all forces known to universe combined uses less security than this.
* **Do NOT forget your passphrases.** Forgetting them = total irrecoverable data loss.

---

## Features

* **Dual-passphrase encryption** (both required)
* **512-bit effective key strength** using Argon2id + ChaCha20-Poly1305
* **50-pass secure erase** on failed decryption attempt 💀💀💀
* Metadata preservation: file size, permissions, modification time
* Corrupted ciphertext (`*.enc`) + self-contained recovery script (`key_restore.py`)

---

## How It Works

1. User provides **two DIFFERENT passphrases**.
2. Each passphrase is processed with **Argon2id** (time=4, memory=128MB, parallelism=10) → produces 32-byte keys.
3. Keys are **XORed** → final encryption key (256-bit effective).
4. File is encrypted using **ChaCha20-Poly1305**.
5. Metadata is encrypted separately.
6. Original file is overwritten with random garbage.
7. `key_restore.py` is generated — **contains no passphrases**, only salts, nonces, and metadata needed for recovery.
8. **One wrong attempt during decryption triggers 50-pass file destruction.**

---

## Security Analysis

 Passphrase Strength

* Recommended: **50+ random characters per passphrase**.
* Total keyspace:

```
Single passphrase: 95^50 possibilities
Two passphrases XORed: 95^50 × 95^50 = 95^100 ≈ 1.86 × 10^197 possibilities
```

 Brute-force Time Estimates

| Attacker      | Hardware                           | Time to brute-force    | Notes            |
| ------------- | ---------------------------------- | ---------------------- | ---------------- |
| Script kiddie | Laptop                             | > lifetime of universe | Impossible       |
| Hacker        | Gaming rig                         | > lifetime of universe | Impossible       |
| State actor   | 1 million-core supercomputer       | > lifetime of universe | Impossible       |
| God-tier PC   | 100× Threadripper + 200× Blackwell | \~2 × 10^178 years     | Still impossible |

💀 Even the **most insane hardware imaginable** can’t brute-force your files if passphrases are strong.
Yeah only when you dont put 1234 as the paraphrase but still if you use 1234 its still impossible because one wrong paraphrase and everythings cooked.

---

## Usage

```bash
# Encrypt a file
python encryptor.py /path/to/file.txt

# Decrypt (run the generated key_restore.py)(Note if running in linux run with sudo command and in windows with adminstrator because the file gets locked once encrypted)
python key_restore.py
```

* During encryption, you’ll be prompted for **two passphrases**.
* During decryption, you’ll need **both exact passphrases**, or the encrypted file will be nuked.

---

## Notes

* **Testing:** Always use dummy files (`test.txt`) before encrypting important files.
* **Storage:** Keep `key_restore.py` **secure** — stealing it doesn’t help without passphrases.
* **SSD Warning:** 50-pass overwrite is most effective on HDDs; SSD wear-leveling may leave remnants.

---

## Disclaimer

* This tool is for **educational purposes only**. Use responsibly.
* Authors are not responsible for lost files.

---

**HellCryptor: Apocalypse-level encryption for the brave 💀🔥**
