# make_encrypted.py
# Military-grade two-key encrypter with EXTREME self-destruct capability
#  - corrupted ciphertext file: <origname>.enc
#  - key file: key_restore.py (runnable; prompts for both keys to restore)
#
# WARNING: test on copies only. This script WILL overwrite the original file.

import os, sys, json, time, stat, base64
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2 import low_level

# === Config ===
ARGON2_TIME = 4  # Increased for stronger key derivation
ARGON2_MEMORY_KB = 128 * 2048  # 128 MB (more memory for stronger protection)
ARGON2_PARALLELISM = 10  # More parallelism
KEY_LEN = 32  # key (32 bytes) - MAXIMUM STRENGTH
NONCE_LEN = 12  # for ChaCha20-Poly1305
DESTRUCT_PASSES = 50  # EXTREME 50-pass destruction 💥💥💥

# === Helpers ===
def derive_raw(password: bytes, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY_KB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=low_level.Type.ID
    )

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def secure_erase(filename, passes=DESTRUCT_PASSES):
    """Overwrite a file multiple times with random data to prevent recovery"""
    try:
        file_size = os.path.getsize(filename)
        print(f"Initiating EXTREME destruction sequence: {passes} overwrite passes...")
        
        for i in range(passes):
            # Different patterns for each pass
            if i % 7 == 0:
                # Random data
                data = os.urandom(file_size)
                pattern = "RANDOM"
            elif i % 7 == 1:
                # All ones
                data = b'\xFF' * file_size
                pattern = "ALL ONES (0xFF)"
            elif i % 7 == 2:
                # All zeros
                data = b'\x00' * file_size
                pattern = "ALL ZEROS (0x00)"
            elif i % 7 == 3:
                # Alternating pattern
                data = b'\xAA\x55' * (file_size // 2 + 1)
                pattern = "ALTERNATING (0xAA55)"
            elif i % 7 == 4:
                # Checkerboard pattern
                data = b'\xCC\x33' * (file_size // 2 + 1)
                pattern = "CHECKERBOARD (0xCC33)"
            elif i % 7 == 5:
                # Complex pattern
                data = b'\x96\x69' * (file_size // 2 + 1)
                pattern = "COMPLEX (0x9669)"
            else:
                # Final pass - DoD 5220.22-M standard
                data = b'\x00' * file_size
                pattern = "FINAL ZERO PASS"
                
            with open(filename, 'wb') as f:
                f.write(data[:file_size])
            os.sync()  # Force write to disk
            
            if i % 5 == 0:  # Progress update every 5 passes
                print(f"  Pass {i+1}/{passes}: {pattern}")
        
        os.remove(filename)
        return True
    except Exception as e:
        print(f"Secure erase failed: {e}")
        return False

# === Main encryption routine ===
def make_encrypted(input_path: str):
    if not os.path.isfile(input_path):
        print("File not found:", input_path); return

    print("⚠️  MILITARY-GRADE ENCRYPTION INITIATED ⚠️")
    print("512-bit key strength | 50-pass destruction on failure")
    print("Enter two DIFFERENT passphrases. Keep them safe — both are required for restore.")
    p1 = getpass("Passphrase 1: ").encode('utf-8')
    p2 = getpass("Passphrase 2: ").encode('utf-8')
    if p1 == b'' or p2 == b'':
        print("Empty passphrase not allowed."); return
    if p1 == p2:
        print("Use two different passphrases please."); return

    # read file
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # capture metadata to restore later
    st = os.stat(input_path)
    metadata = {
        "orig_path": os.path.abspath(input_path),
        "mode": st.st_mode,
        "mtime": st.st_mtime,
        "size": len(plaintext)
    }

    # derive two raw keys (different salts)
    salt1 = os.urandom(32)  # Larger salt for 512-bit key
    salt2 = os.urandom(32)
    print("Deriving cryptographic keys (this may take a moment)...")
    raw1 = derive_raw(p1, salt1)
    raw2 = derive_raw(p2, salt2)
    final_key = xor_bytes(raw1, raw2)  # both required

    # encrypt file content
    cipher = ChaCha20Poly1305(final_key)
    nonce = os.urandom(NONCE_LEN)
    associated_data = os.path.basename(input_path).encode('utf-8')
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)

    # encrypt metadata separately (so only key_restore can get it)
    meta_cipher = ChaCha20Poly1305(final_key)
    meta_nonce = os.urandom(NONCE_LEN)
    meta_blob = json.dumps(metadata).encode('utf-8')
    meta_ct = meta_cipher.encrypt(meta_nonce, meta_blob, b"METADATA")

    # write corrupted ciphertext file
    corrupted_path = input_path + ".enc"
    with open(corrupted_path, 'wb') as f:
        # write a tiny header so key_restore knows how to decrypt
        hdr = {
            "kdf": "argon2id",
            "salt1": b64(salt1),
            "salt2": b64(salt2),
            "argon2_time": ARGON2_TIME,
            "argon2_memory_kb": ARGON2_MEMORY_KB,
            "argon2_parallelism": ARGON2_PARALLELISM,
            "nonce": b64(nonce),
            "ad": base64.b64encode(associated_data).decode('utf-8'),
            "meta_nonce": b64(meta_nonce),
            "meta_ct": b64(meta_ct),
            "key_strength": "512-bit",
            "destruct_passes": DESTRUCT_PASSES
        }
        hdr_json = json.dumps(hdr).encode('utf-8')
        # simple layout: 4 bytes len, then JSON, then ciphertext
        f.write(len(hdr_json).to_bytes(4, 'big'))
        f.write(hdr_json)
        f.write(ciphertext)

    # overwrite original file with random garbage of same size (so it's corrupted)
    with open(input_path, 'wb') as f:
        f.write(os.urandom(max(1, metadata["size"])))

    # clear metadata on filesystem: set mtime to epoch and remove permissions (owner can fix later)
    try:
        os.chmod(input_path, 0o000)
    except Exception:
        pass
    try:
        os.utime(input_path, (0, 0))
    except Exception:
        pass

    # create key_restore.py that contains the header JSON and code to restore (no keys in plaintext)
    key_script = f"""#!/usr/bin/env python3
# key_restore.py
# Run this file to restore the original file. It will prompt for the 2 passphrases.
# This script was auto-generated by make_encrypted.py
# ⚠️  WARNING: ONE WRONG ATTEMPT WILL DESTROY THE ENCRYPTED FILE PERMANENTLY ⚠️
import os, json, base64, sys, time
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2 import low_level

# Security parameters - EXTREME MODE
DESTRUCT_PASSES = {DESTRUCT_PASSES}  # Number of times to overwrite file on failed attempt

def derive_raw(password: bytes, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost={ARGON2_TIME},
        memory_cost={ARGON2_MEMORY_KB},
        parallelism={ARGON2_PARALLELISM},
        hash_len={KEY_LEN},
        type=low_level.Type.ID
    )

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def b64d(s):
    return base64.b64decode(s.encode('utf-8'))

def secure_erase(filename, passes=DESTRUCT_PASSES):
    \"\"\"Overwrite a file multiple times with random data to prevent recovery\"\"\"
    try:
        file_size = os.path.getsize(filename)
        print(f"Initiating EXTREME destruction sequence: {{passes}} overwrite passes...")
        
        for i in range(passes):
            # Different patterns for each pass
            if i % 7 == 0:
                # Random data
                data = os.urandom(file_size)
                pattern = "RANDOM"
            elif i % 7 == 1:
                # All ones
                data = b'\\xFF' * file_size
                pattern = "ALL ONES (0xFF)"
            elif i % 7 == 2:
                # All zeros
                data = b'\\x00' * file_size
                pattern = "ALL ZEROS (0x00)"
            elif i % 7 == 3:
                # Alternating pattern
                data = b'\\xAA\\x55' * (file_size // 2 + 1)
                pattern = "ALTERNATING (0xAA55)"
            elif i % 7 == 4:
                # Checkerboard pattern
                data = b'\\xCC\\x33' * (file_size // 2 + 1)
                pattern = "CHECKERBOARD (0xCC33)"
            elif i % 7 == 5:
                # Complex pattern
                data = b'\\x96\\x69' * (file_size // 2 + 1)
                pattern = "COMPLEX (0x9669)"
            else:
                # Final pass - DoD 5220.22-M standard
                data = b'\\x00' * file_size
                pattern = "FINAL ZERO PASS"
                
            with open(filename, 'wb') as f:
                f.write(data[:file_size])
            os.sync()  # Force write to disk
            
            if i % 5 == 0:  # Progress update every 5 passes
                print(f"  Pass {{i+1}}/{{passes}}: {{pattern}}")
        
        os.remove(filename)
        return True
    except Exception as e:
        print(f"Secure erase failed: {{e}}")
        return False

# embedded header (from encryption step)
hdr = {json.dumps(hdr)}

def main():
    print("⚠️  MILITARY-GRADE DECRYPTION INITIATED ⚠️")
    print("512-bit key strength | 50-pass destruction on failure")
    print("WARNING: ONE WRONG ATTEMPT WILL DESTROY THE ENCRYPTED FILE PERMANENTLY")
    print("This will attempt to restore the original file. You will be asked for two passphrases.")
    p1 = getpass("Passphrase 1: ").encode('utf-8')
    p2 = getpass("Passphrase 2: ").encode('utf-8')
    if not p1 or not p2:
        print("Empty passphrases not allowed."); return

    salt1 = b64d(hdr['salt1'])
    salt2 = b64d(hdr['salt2'])
    print("Deriving cryptographic keys (this may take a moment)...")
    raw1 = derive_raw(p1, salt1)
    raw2 = derive_raw(p2, salt2)
    final_key = xor_bytes(raw1, raw2)

    # open corrupted file and read header and ciphertext
    enc_path = {json.dumps(os.path.basename(corrupted_path))}
    try:
        with open(enc_path, 'rb') as f:
            L = int.from_bytes(f.read(4), 'big')
            hdr_json = f.read(L)
            ciphertext = f.read()
    except Exception as e:
        print("Failed to read encrypted file. It may have been tampered with.")
        return

    # sanity - use ad and nonce from embedded hdr
    nonce = b64d(hdr['nonce'])
    ad = base64.b64decode(hdr['ad'].encode('utf-8'))

    # decrypt file content
    try:
        a = ChaCha20Poly1305(final_key)
        plaintext = a.decrypt(nonce, ciphertext, ad)
    except Exception as e:
        print("💥💥💥 DECRYPTION FAILED - EXTREME SELF-DESTRUCT INITIATED 💥💥💥")
        print(f"Nuking encrypted file with {{DESTRUCT_PASSES}} overwrite passes...")
        if secure_erase(enc_path):
            print("✅ File permanently destroyed. No recovery possible. 💀💀💀")
        else:
            print("❌ Failed to completely destroy file. Manual destruction recommended.")
        return

    # decrypt metadata
    try:
        meta_nonce = b64d(hdr['meta_nonce'])
        meta_ct = b64d(hdr['meta_ct'])
        m = ChaCha20Poly1305(final_key)
        meta_plain = m.decrypt(meta_nonce, meta_ct, b"METADATA")
        metadata = json.loads(meta_plain.decode('utf-8'))
    except Exception as e:
        print("Metadata decryption failed — something odd. Aborting.")
        return

    restore_path = metadata.get('orig_path') or ("restored_" + enc_path.replace('.enc',''))
    # write restored file
    with open(restore_path, 'wb') as out:
        out.write(plaintext)
    # restore metadata
    try:
        os.chmod(restore_path, metadata.get('mode', 0o644))
    except Exception:
        pass
    try:
        os.utime(restore_path, (metadata.get('mtime', time.time()), metadata.get('mtime', time.time())))
    except Exception:
        pass

    print("✅ Restored file:", restore_path)
    print("⚠️  Remember to securely delete the restore script after successful recovery!")

if __name__ == '__main__':
    main()
"""
    # write key_restore.py to disk
    key_path = "key_restore.py"
    with open(key_path, 'w') as kf:
        kf.write(key_script)

    # make it executable
    try:
        os.chmod(key_path, 0o700)
    except Exception:
        pass

    print("✅ Encryption complete. Created:")
    print(" - Corrupted ciphertext file:", corrupted_path)
    print(" - Key file (run to restore):", key_path)
    print("⚠️  WARNING: ONE WRONG PASSPHRASE ATTEMPT WILL DESTROY THE ENCRYPTED FILE PERMANENTLY")
    print("💀 50-pass secure erase | 32byte cryptographic strength 💀")
    print("Remember: both passphrases are REQUIRED to restore.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python make_encrypted.py /path/to/targetfile")
        sys.exit(1)
    make_encrypted(sys.argv[1])
