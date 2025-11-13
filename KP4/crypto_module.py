from Crypto.Util import Counter
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

BLOCK_SIZES = {
    'DES': 8,
    '3DES': 8,
    'AES': 16
}

def derive_key(key_bytes, alg):
    """
    Normalize key to allowed sizes:
    - DES: 8 bytes
    - 3DES: 16 or 24 bytes (return 24 if available else 16 padded)
    - AES: 16/24/32 bytes (return 16/24/32 by preference)
    """
    if alg == 'DES':
        return key_bytes[:8].ljust(8, b'\0')
    if alg == '3DES':
        if len(key_bytes) >= 24:
            return key_bytes[:24]
        if len(key_bytes) >= 16:
            return key_bytes[:16]
        return key_bytes.ljust(16, b'\0')
    if alg == 'AES':
        if len(key_bytes) >= 32:
            return key_bytes[:32]
        if len(key_bytes) >= 24:
            return key_bytes[:24]
        return key_bytes.ljust(16, b'\0')
    raise ValueError("Unknown algorithm")

def get_cipher(alg, mode, key, iv=None, nonce=None):
    # Mode strings: CBC, ECB, CFB, OFB, CTR, GCM
    m = mode.upper()
    if alg == 'DES':
        if m == 'CBC': return DES.new(key, DES.MODE_CBC, iv=iv)
        if m == 'ECB': return DES.new(key, DES.MODE_ECB)
        if m == 'CFB': return DES.new(key, DES.MODE_CFB, iv=iv)
        if m == 'OFB': return DES.new(key, DES.MODE_OFB, iv=iv)
        if m == 'CTR': return DES.new(key, DES.MODE_CTR)
    if alg == '3DES':
        if m == 'CBC': return DES3.new(key, DES3.MODE_CBC, iv=iv)
        if m == 'ECB': return DES3.new(key, DES3.MODE_ECB)
        if m == 'CFB': return DES3.new(key, DES3.MODE_CFB, iv=iv)
        if m == 'OFB': return DES3.new(key, DES3.MODE_OFB, iv=iv)
        if m == 'CTR': return DES3.new(key, DES3.MODE_CTR)
    if alg == 'AES':
        if m == 'CBC': return AES.new(key, AES.MODE_CBC, iv=iv)
        if m == 'ECB': return AES.new(key, AES.MODE_ECB)
        if m == 'CFB': return AES.new(key, AES.MODE_CFB, iv=iv)
        if m == 'OFB': return AES.new(key, AES.MODE_OFB, iv=iv)
        if m == 'CTR': return AES.new(key, AES.MODE_CTR)
        if m == 'GCM': return AES.new(key, AES.MODE_GCM, nonce=nonce)
    raise ValueError("Unsupported mode or algorithm")

def encrypt_bytes(alg, mode, key_bytes, plaintext_bytes):
    alg = alg.upper()
    mode = mode.upper()
    block = BLOCK_SIZES[alg]
    key = derive_key(key_bytes, alg)
    iv = None
    nonce = None
    tag = None

    if mode in ('CBC','CFB','OFB'):
        iv = get_random_bytes(block)

    if mode == 'GCM':
        nonce = get_random_bytes(12)

    if mode == 'CTR':
        iv = get_random_bytes(block)
        initial_value = int.from_bytes(iv, byteorder='big')
        ctr_obj = Counter.new(block * 8, initial_value=initial_value)

        if alg == 'DES':
            cipher = DES.new(key, DES.MODE_CTR, counter=ctr_obj)
        elif alg == '3DES':
            cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr_obj)
        elif alg == 'AES':
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr_obj)
        else:
            raise ValueError("Unsupported algorithm for CTR")
    else:
        cipher = get_cipher(alg, mode, key, iv=iv, nonce=nonce)

    if mode in ('ECB','CBC'):
        ct = cipher.encrypt(pad(plaintext_bytes, block))
    elif mode == 'GCM':
        ct, tag = cipher.encrypt_and_digest(plaintext_bytes)
    else:
        ct = cipher.encrypt(plaintext_bytes)

    return {
        'ciphertext': base64.b64encode(ct).decode(),
        'iv': base64.b64encode(iv).decode() if iv else None,
        'nonce': base64.b64encode(nonce).decode() if nonce else None,
        'tag': base64.b64encode(tag).decode() if tag else None
    }

def decrypt_bytes(alg, mode, key_bytes, b64_ct, b64_iv=None, b64_nonce=None, b64_tag=None):
    alg = alg.upper()
    mode = mode.upper()
    block = BLOCK_SIZES[alg]
    key = derive_key(key_bytes, alg)
    ct = base64.b64decode(b64_ct)
    iv = base64.b64decode(b64_iv) if b64_iv else None
    nonce = base64.b64decode(b64_nonce) if b64_nonce else None
    tag = base64.b64decode(b64_tag) if b64_tag else None

    if mode == 'CTR':
        if not iv:
            raise ValueError("IV is required for CTR decryption")
        initial_value = int.from_bytes(iv, byteorder='big')
        ctr_obj = Counter.new(block * 8, initial_value=initial_value)
        if alg == 'DES':
            cipher = DES.new(key, DES.MODE_CTR, counter=ctr_obj)
        elif alg == '3DES':
            cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr_obj)
        elif alg == 'AES':
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr_obj)
        else:
            raise ValueError("Unsupported algorithm for CTR")
        pt = cipher.decrypt(ct)
        return pt

    if alg == 'AES' and mode == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt

    cipher = get_cipher(alg, mode, key, iv=iv, nonce=nonce)
    if mode in ('ECB','CBC'):
        pt = unpad(cipher.decrypt(ct), block)
    else:
        pt = cipher.decrypt(ct)
    return pt
