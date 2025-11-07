from PIL import Image
import os, zipfile, tempfile, shutil, base64
from typing import List, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DELIMITER = b"<-VAN-GONOGRAPHY->"

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    return salt + f.encrypt(data)

def decrypt_data(data: bytes, password: str) -> bytes:
    salt = data[:16]
    ct = data[16:]
    key = _derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(ct)

def _embed_data(image_path: str, data: bytes, output_path: str):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    data_with_delim = data + DELIMITER
    bits = ''.join(format(b, '08b') for b in data_with_delim)
    w,h = img.size
    capacity = w*h*3
    if len(bits) > capacity:
        raise ValueError('data too large for image')
    pix = img.load()
    idx = 0
    for y in range(h):
        for x in range(w):
            r,g,b = list(pix[x,y])
            if idx < len(bits):
                r = (r & ~1) | int(bits[idx]); idx+=1
            if idx < len(bits):
                g = (g & ~1) | int(bits[idx]); idx+=1
            if idx < len(bits):
                b = (b & ~1) | int(bits[idx]); idx+=1
            pix[x,y] = (r,g,b)
            if idx>=len(bits):
                break
        if idx>=len(bits):
            break
    img.save(output_path)

def _extract_data(image_path: str) -> bytes:
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pix = img.load()
    w,h = img.size
    bits = ''
    delim_bits = ''.join(format(b,'08b') for b in DELIMITER)
    for y in range(h):
        for x in range(w):
            r,g,b = pix[x,y]
            bits += str(r&1)+str(g&1)+str(b&1)
            if delim_bits in bits:
                break
        if delim_bits in bits:
            break
    data_bits = bits.split(delim_bits)[0]
    bts = bytearray()
    for i in range(0,len(data_bits),8):
        chunk = data_bits[i:i+8]
        if len(chunk)==8:
            bts.append(int(chunk,2))
    return bytes(bts)

def hide_files_into_image(cover_path: str, file_paths: List[str], output_path: str,
                          encrypt: bool=False, password: Optional[str]=None, temp_dir: Optional[str]=None):
    cleanup = False
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp()
        cleanup = True
    try:
        if len(file_paths)==1:
            with open(file_paths[0],'rb') as f:
                payload = f.read()
        else:
            zp = os.path.join(temp_dir,'archive.zip')
            with zipfile.ZipFile(zp,'w',compression=zipfile.ZIP_DEFLATED) as zf:
                for p in file_paths:
                    zf.write(p, arcname=os.path.basename(p))
            with open(zp,'rb') as f:
                payload = f.read()
        if encrypt:
            if not password:
                raise ValueError('password required for encryption')
            payload = encrypt_data(payload, password)
        _embed_data(cover_path, payload, output_path)
    finally:
        if cleanup:
            try: shutil.rmtree(temp_dir)
            except: pass

def extract_file_from_image(image_path: str, output_dir: str, password: Optional[str]=None) -> str:
    data = _extract_data(image_path)
    if password:
        data = decrypt_data(data, password)
    if data.startswith(b'PK\x03\x04'):
        out = os.path.join(output_dir, 'extracted_archive.zip')
    else:
        out = os.path.join(output_dir, 'extracted_file.bin')
    with open(out,'wb') as f:
        f.write(data)
    return out
    
