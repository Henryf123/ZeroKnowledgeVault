import os 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600_000
CHUNK_SIZE = 10 * 1024 * 1024 
ENCRYPTED_CHUNK_SIZE = 12 + CHUNK_SIZE + 16 

def derive_kek(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode())

def _derive_file_key(master_dek: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"vault-file-key",
    )
    return hkdf.derive(master_dek)

def _derive_backup_key(master_dek: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"vault-backup-key",
    )
    return hkdf.derive(master_dek)

def encrypt_payload(data: bytes, key: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, aad)

def decrypt_payload(en_data: bytes, key: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = en_data[:12]
    return aesgcm.decrypt(nonce, en_data[12:], aad)

def stream_encrypt(in_path, out_path, master_dek, file_uuid: str):
    file_salt = os.urandom(16)
    file_key = _derive_file_key(master_dek, file_salt)
    aesgcm = AESGCM(file_key)
    
    aad_base = file_uuid.encode()
    
    with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
        f_out.write(file_salt)
        chunk_index = 0
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            
            chunk_aad = aad_base + chunk_index.to_bytes(4, 'big')
            
            nonce = file_salt[:4] + chunk_index.to_bytes(8, 'big')
            f_out.write(nonce + aesgcm.encrypt(nonce, chunk, chunk_aad))
            chunk_index += 1

def stream_decrypt(in_path, out_path, master_dek, file_uuid: str):
    aad_base = file_uuid.encode()
    
    with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
        file_salt = f_in.read(16)
        file_key = _derive_file_key(master_dek, file_salt)
        aesgcm = AESGCM(file_key)
        
        chunk_index = 0
        while True:
            chunk = f_in.read(ENCRYPTED_CHUNK_SIZE)
            if not chunk:
                break
            
            chunk_aad = aad_base + chunk_index.to_bytes(4, 'big')
            nonce = chunk[:12]
            payload = chunk[12:]
            f_out.write(aesgcm.decrypt(nonce, payload, chunk_aad))
            chunk_index += 1