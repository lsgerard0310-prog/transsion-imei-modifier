#!/usr/bin/env python3
"""
TRANSSION NVD Decryption Tool
Desencripta datos NVD usando clave AES extraída de lk_a.bin
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Clave maestra TRANSSION (extraída de lk_a.bin)
AES_KEY_STRING = "FunAESKey0015y83rEslYufMeXITEZ3VM0SBetu#QgsAaLl7RzwY1KPeb8j9yxJe6TNRm+C4d2fkdeuK8bgER4HmfBY2BYCVKkWyA5uplo2ioQ6vjNXyxbTt5YW8v5#09etkJVgD4cSwDJw=5WfNxRqiIo+tgoS8d2=aTws9lCP5TubMlycIDPfAwLpsAHkodh7PYM0qwZNX14T02QRFr8+vYMxzu7chDvGmzS3BbyE1NZ5TXAxSadGW=3+1zVUmd2Ja9uvH3BDO648rslH5JCj@vG9B81jpA9Jh3o=QkPXOjJf#AODiTxdsNURQpefquKa37QYxrl8HcZ6t#bC03L+1eWsRpce7@MFjGkL1IRUV@uHGUfLyxX5K87qB5@b8DGixSkz97+TlwDxb1NHims=zlXKRHOBUsIyG#7dYX6@=e5zGDbdusO#jxATMTP3GU=dF@wHbzaOiuNof5wdL70ES@r1jov#Dsn8ilY9rt3mRhCFs31RnUAfrE=xo3FBg+aPmnC04SLH9ewG@k3jVydIWsrTiwyAKL4QDbtSNBp7@yC+n8Ovj3XmBGIHqWlYPVOBfjZIieMn7DE6ev2a@ONYrfpBTbXchViat36l2EwCgolV6B9GqKrATet#QDFHqjdB2uNhPWcl1Hq@ji+CzsMa8kY=A3yoLG2jTf9tq#QVn3N#HWBrftI@n2LsKJE=Nx7HA2qod+6jlKCyNI19tc5prLvOJ9m1xitKS4bgkrzQqR=rqZ38aH#tXYh50v5UdGCiXjKLz6ZP#1yer3EBc2#YMgHKU"

TARGET_IMEI = "357577941359537"

# Datos encriptados NV0S (64 bytes - sin espacios)
NV0S_ENCRYPTED = "004ea430ab6dbfb935c9d46bf82b66f4ffb15bcf5492404646ca362b9407d4990b8b505dd30253" \
                 "9c8e6284918511ecfe3fc89e2ee39625b9b8df047fd94747ca859116" \
                 "3a6bdeedd15900c0f534deee8cc642b"

# Datos encriptados NV01 (32 bytes - CORREGIDO sin espacios)
NV01_ENCRYPTED = "25b844d239720 5b98d9cc22a211c654f64d01f548bbd86e4a1e73e29cac8b5e2".replace(" ", "")

def normalize_aes_key(key_string):
    """Normaliza clave usando SHA256"""
    h = SHA256.new()
    h.update(key_string.encode('utf-8'))
    return h.digest()

def try_decrypt_cbc(ciphertext, key, iv=None):
    """Desencripta con AES-CBC"""
    try:
        if iv is None:
            iv = ciphertext[:16]
            data = ciphertext[16:]
        else:
            data = ciphertext
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(data)
        return plaintext, iv
    except Exception as e:
        print(f"    [-] Error: {e}")
        return None, None

def try_decrypt_ecb(ciphertext, key):
    """Desencripta con AES-ECB"""
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except Exception as e:
        print(f"    [-] Error: {e}")
        return None

def find_imei(data, target):
    """Busca IMEI en datos desencriptados"""
    try:
        text = data.decode('utf-8', errors='ignore')
        if target in text:
            idx = text.find(target)
            return True, idx, text[max(0, idx-30):idx+len(target)+30]
    except:
        pass
    
    hex_imei = target.encode('utf-8').hex()
    hex_data = data.hex()
    if hex_imei in hex_data:
        idx = hex_data.find(hex_imei)
        start = max(0, idx-60)
        end = idx+len(hex_imei)+60
        return True, idx//2, hex_data[start:end]
    
    return False, -1, ""

print("\n" + "=" * 80)
print("TRANSSION NVD DECRYPTION TOOL")
print("=" * 80)

# Preparar clave
aes_key = normalize_aes_key(AES_KEY_STRING)
print(f"\n[+] Clave AES normalizada (SHA256):")
print(f"    {aes_key.hex()}")
print(f"    Tamaño: {len(aes_key)} bytes")

# Convertir datos hex a bytes
print(f"\n[*] Procesando datos encriptados...")
try:
    nv0s_data = bytes.fromhex(NV0S_ENCRYPTED)
    nv01_data = bytes.fromhex(NV01_ENCRYPTED)
    print(f"[+] NV0S: {len(nv0s_data)} bytes")
    print(f"[+] NV01: {len(nv01_data)} bytes")
except ValueError as e:
    print(f"[-] Error al procesar hex: {e}")
    print(f"[DEBUG] NV0S length: {len(NV0S_ENCRYPTED)}")
    print(f"[DEBUG] NV01 length: {len(NV01_ENCRYPTED)}")
    exit(1)

# ========================================================================
# DESENCRIPTAR NV0S
# ========================================================================
print("\n" + "=" * 80)
print("DESENCRIPTANDO NV0S")
print("=" * 80)
print(f"\nHex encriptado:\n{nv0s_data.hex()}\n")

print("[*] Intentando AES-CBC con IV en primeros 16 bytes...")
plaintext_cbc, iv_used = try_decrypt_cbc(nv0s_data, aes_key)
if plaintext_cbc:
    print(f"[+] ÉXITO - Desencriptado (CBC):")
    print(f"    IV: {iv_used.hex()}")
    print(f"    Hex: {plaintext_cbc.hex()}")
    print(f"    ASCII: {plaintext_cbc}\n")
    
    found, pos, context = find_imei(plaintext_cbc, TARGET_IMEI)
    if found:
        print(f"[✓✓✓] IMEI '{TARGET_IMEI}' ENCONTRADO!")
        print(f"    Posición: byte {pos}")
        print(f"    Contexto: {context}\n")
    else:
        print(f"[-] IMEI no encontrado en este resultado\n")

print("[*] Intentando AES-ECB...")
plaintext_ecb = try_decrypt_ecb(nv0s_data, aes_key)
if plaintext_ecb:
    print(f"[+] ÉXITO - Desencriptado (ECB):")
    print(f"    Hex: {plaintext_ecb.hex()}")
    print(f"    ASCII: {plaintext_ecb}\n")
    
    found, pos, context = find_imei(plaintext_ecb, TARGET_IMEI)
    if found:
        print(f"[✓✓✓] IMEI '{TARGET_IMEI}' ENCONTRADO!")
        print(f"    Posición: byte {pos}")
        print(f"    Contexto: {context}\n")

# ========================================================================
# DESENCRIPTAR NV01
# ========================================================================
print("\n" + "=" * 80)
print("DESENCRIPTANDO NV01")
print("=" * 80)
print(f"\nHex encriptado:\n{nv01_data.hex()}\n")

print("[*] Intentando AES-CBC...")
plaintext_cbc, iv_used = try_decrypt_cbc(nv01_data, aes_key)
if plaintext_cbc:
    print(f"[+] ÉXITO - Desencriptado (CBC):")
    print(f"    Hex: {plaintext_cbc.hex()}")
    print(f"    ASCII: {plaintext_cbc}\n")

print("[*] Intentando AES-ECB...")
plaintext_ecb = try_decrypt_ecb(nv01_data, aes_key)
if plaintext_ecb:
    print(f"[+] ÉXITO - Desencriptado (ECB):")
    print(f"    Hex: {plaintext_ecb.hex()}")
    print(f"    ASCII: {plaintext_ecb}\n")

print("=" * 80)
print("FIN DEL ANÁLISIS")
print("=" * 80 + "\n")
