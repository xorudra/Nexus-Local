from pathlib import Path
import os, json, base64, hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Requires: pip install cryptography

# Helper: key derivation

def derive_key(password: str, salt: bytes, iterations: int=600_000) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)

# Encrypt keys dict

def encrypt_keys(keys: dict, password: str, out_path: Path):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(keys).encode()
    ct = aesgcm.encrypt(nonce, plaintext, None)
    payload = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ct).decode(),
    }
    out_path.write_text(json.dumps(payload), encoding='utf-8')
    # Note: on Windows, chmod 0600 is advisory only — the setup guide must tell the user to keep the folder private (NTFS permissions).
    os.chmod(out_path, 0o600)

# Decrypt

def decrypt_keys(enc_path: Path, password: str)->dict:
    data = json.loads(enc_path.read_text(encoding='utf-8'))
    salt = base64.b64decode(data['salt'])
    nonce = base64.b64decode(data['nonce'])
    ct = base64.b64decode(data['ciphertext'])
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return json.loads(plaintext)

# Quick self-test

if __name__=='__main__':
    test_keys={'openai':'key1','gemini':'key2'}
    test_enc=Path('keys.enc')
    pw='testpassword'
    encrypt_keys(test_keys,pw,test_enc)
    print('Encrypted:', test_enc.read_text()[:30], '...')
    dec=decrypt_keys(test_enc,pw)
    
    # Clean up
    test_enc.unlink()
