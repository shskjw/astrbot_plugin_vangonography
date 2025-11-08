import base64
import os
import shutil
from typing import Optional

from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 1. 代码质量与编码规范: 导入 astrbot logger
from astrbot.api import logger

# Delimiters for separating filename and content, and for marking end of data
FILENAME_DELIMITER = b"<-F-N->"
DATA_DELIMITER = b"<-V-G->"


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    return salt + fernet.encrypt(data)


def decrypt_data(data: bytes, password: str) -> bytes:
    salt, ciphertext = data[:16], data[16:]
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext)


def _embed_data(image_path: str, data: bytes, output_path: str):
    image = Image.open(image_path).convert('RGB')
    width, height = image.size
    
    # Add delimiter to mark the end of the data
    data_with_delimiter = data + DATA_DELIMITER
    bits_to_embed = ''.join(f'{byte:08b}' for byte in data_with_delimiter)
    
    required_pixels = -(-len(bits_to_embed) // 3)
    current_pixels = width * height

    # Automatically resize image if it's too small
    if required_pixels > current_pixels:
        scale_factor = (required_pixels / current_pixels) ** 0.5
        new_width = int(width * scale_factor) + 1
        new_height = int(height * scale_factor) + 1
        image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        width, height = new_width, new_height

    bit_index = 0
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            # Embed bits into the LSB of each color channel
            if bit_index < len(bits_to_embed):
                r = (r & ~1) | int(bits_to_embed[bit_index])
                bit_index += 1
            if bit_index < len(bits_to_embed):
                g = (g & ~1) | int(bits_to_embed[bit_index])
                bit_index += 1
            if bit_index < len(bits_to_embed):
                b = (b & ~1) | int(bits_to_embed[bit_index])
                bit_index += 1
            
            pixels[x, y] = (r, g, b)
            if bit_index >= len(bits_to_embed):
                break
        if bit_index >= len(bits_to_embed):
            break
            
    image.save(output_path, 'PNG')


# 2. 潜在缺陷或问题: 修复严重性能瓶颈
def _extract_data(image_path: str) -> bytes:
    image = Image.open(image_path).convert('RGB')
    width, height = image.size
    pixels = image.load()
    
    extracted_bytes = bytearray()
    bit_buffer = []
    delimiter_len = len(DATA_DELIMITER)
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bit_buffer.extend([str(r & 1), str(g & 1), str(b & 1)])
            
            while len(bit_buffer) >= 8:
                byte_str = "".join(bit_buffer[:8])
                del bit_buffer[:8]
                extracted_bytes.append(int(byte_str, 2))
                
                # Efficiently check for the delimiter at the end of the byte array
                if len(extracted_bytes) >= delimiter_len:
                    if extracted_bytes[-delimiter_len:] == DATA_DELIMITER:
                        return bytes(extracted_bytes[:-delimiter_len]) # Return data without delimiter
    
    # If delimiter was not found, it might mean the file is corrupt or wasn't created by this tool
    raise ValueError("数据分隔符未找到，文件可能已损坏或格式不正确。")


def hide_file_into_image(cover_path: str, file_path: str, file_name: str, output_path: str,
                         encrypt: bool = False, password: Optional[str] = None):
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # Combine filename and file content into a single payload
        payload = file_name.encode('utf-8') + FILENAME_DELIMITER + file_content
        
        if encrypt:
            if not password:
                raise ValueError('加密需要提供密码')
            payload = encrypt_data(payload, password)
            
        _embed_data(cover_path, payload, output_path)
    except Exception as e:
        logger.error(f"隐藏文件时出错: {e}", exc_info=True)
        raise


def extract_file_from_image(image_path: str, output_dir: str, password: Optional[str] = None) -> str:
    extracted_data = _extract_data(image_path)
    
    if password:
        try:
            extracted_data = decrypt_data(extracted_data, password)
        except Exception:
            # Re-raise with a user-friendly message
            raise ValueError("解密失败，密码错误或文件已损坏。")

    try:
        filename_bytes, file_content = extracted_data.split(FILENAME_DELIMITER, 1)
        filename = filename_bytes.decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError("无法解析文件名，文件可能已损坏或未使用此工具创建。")

    output_file_path = os.path.join(output_dir, filename)
    
    with open(output_file_path, 'wb') as f:
        f.write(file_content)
        
    return output_file_path
