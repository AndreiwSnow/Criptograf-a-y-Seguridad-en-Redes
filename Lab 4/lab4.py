#!/usr/bin/env python3
from Cryptodome.Cipher import AES, DES, DES3
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import base64, binascii

# ---------- utilidades ----------
def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode().upper()

def from_hex_or_b64_or_text(s: str) -> bytes:
    s = s.strip()
    # hex
    try:
        return bytes.fromhex(s)
    except Exception:
        pass
    # base64
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        pass
    # texto plano
    return s.encode("utf-8")

def ensure_valid_3des_key_random(k: bytes) -> bytes:
    """
    Si la clave 3DES no es aceptada (por debilidad/paridad), modifica bytes
    aleatoriamente hasta que la librería la acepte. Uso deliberado de aleatoriedad.
    """
    if len(k) != 24:
        raise ValueError("La clave 3DES debe tener 24 bytes antes de validar.")
    intentos = 0
    kb = bytearray(k)
    while intentos < 200:
        try:
            DES3.new(bytes(kb), DES3.MODE_CBC, iv=b"\x00"*8)
            return bytes(kb)
        except ValueError:
            # Cambia aleatoriamente una posición y su valor
            pos = get_random_bytes(1)[0] % 24
            kb[pos] = (kb[pos] + get_random_bytes(1)[0]) & 0xFF
            intentos += 1
    raise ValueError("No se pudo ajustar una clave 3DES válida tras múltiples intentos.")

def ajustar_clave(key_text: str, target_len: int, algoritmo: str) -> tuple[bytes, str]:
    """
    Ajusta la clave según consigna:
    - Si es menor, completa con bytes aleatorios (get_random_bytes).
    - Si es mayor, trunca.
    - Devuelve (clave_ajustada, accion_realizada).
    - Para 3DES, valida y ajusta aleatoriamente si es inválida.
    """
    k = key_text.encode("utf-8")
    accion = "sin cambios"
    if len(k) < target_len:
        k = k + get_random_bytes(target_len - len(k))
        accion = "relleno aleatorio"
    elif len(k) > target_len:
        k = k[:target_len]
        accion = "truncado"

    if algoritmo == "3DES":
        k = ensure_valid_3des_key_random(k)

    return k, accion

def require_iv(iv_text: str, needed_len: int, nombre: str) -> bytes:
    iv = from_hex_or_b64_or_text(iv_text)
    if len(iv) != needed_len:
        raise ValueError(f"IV inválido para {nombre}: se requieren {needed_len} bytes exactos.")
    return iv

# ---------- funciones por algoritmo (cifrar/descifrar) ----------
def cifrar_des(key: bytes, iv: bytes, pt: bytes) -> bytes:
    c = DES.new(key, DES.MODE_CBC, iv=iv)
    return c.encrypt(pad(pt, DES.block_size))

def descifrar_des(key: bytes, iv: bytes, ct: bytes) -> bytes:
    c = DES.new(key, DES.MODE_CBC, iv=iv)
    return unpad(c.decrypt(ct), DES.block_size)

def cifrar_3des(key: bytes, iv: bytes, pt: bytes) -> bytes:
    c = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return c.encrypt(pad(pt, DES3.block_size))

def descifrar_3des(key: bytes, iv: bytes, ct: bytes) -> bytes:
    c = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return unpad(c.decrypt(ct), DES3.block_size)

def cifrar_aes(key: bytes, iv: bytes, pt: bytes) -> bytes:
    c = AES.new(key, AES.MODE_CBC, iv=iv)
    return c.encrypt(pad(pt, AES.block_size))

def descifrar_aes(key: bytes, iv: bytes, ct: bytes) -> bytes:
    c = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(c.decrypt(ct), AES.block_size)

# ---------- I/O ----------
def pedir_datos():
    print("=== Sistema de Cifrado Simétrico (CBC) ===")
    texto = input("Texto a cifrar: ").strip().encode("utf-8")

    print("\n-- DES --")
    key_des = input("Key DES: ").strip()
    iv_des  = input("IV DES (hex/base64/texto, 8 bytes): ").strip()

    print("\n-- 3DES --")
    key_3des = input("Key 3DES: ").strip()
    iv_3des  = input("IV 3DES (hex/base64/texto, 8 bytes): ").strip()

    print("\n-- AES-256 --")
    key_aes = input("Key AES-256: ").strip()
    iv_aes  = input("IV AES (hex/base64/texto, 16 bytes): ").strip()

    return texto, (key_des, iv_des), (key_3des, iv_3des), (key_aes, iv_aes)

def imprimir_resultado(nombre: str, key: bytes, accion: str, iv: bytes, ct: bytes, pt: bytes):
    print(f"\n[{nombre}] Resultados")
    print(f" - Ajuste de clave  : {accion}")
    print(f" - Clave final (hex): {to_hex(key)}")
    print(f" - IV (hex)         : {to_hex(iv)}")
    print(f" - Cifrado (hex)    : {to_hex(ct)}")
    print(f" - Cifrado (b64)    : {base64.b64encode(ct).decode()}")
    print(f" - Descifrado (utf8): {pt.decode('utf-8', errors='replace')}")

# ---------- main ----------
if __name__ == "__main__":
    try:
        texto, (key_des_t, iv_des_t), (key_3des_t, iv_3des_t), (key_aes_t, iv_aes_t) = pedir_datos()

        # Ajuste de claves (relleno aleatorio o truncado) + impresión de clave final
        k_des,  act_des  = ajustar_clave(key_des_t, 8,  "DES")
        k_3des, act_3des = ajustar_clave(key_3des_t, 24, "3DES")
        k_aes,  act_aes  = ajustar_clave(key_aes_t, 32, "AES")

        # IV: obligatorio, tamaño exacto
        iv_des  = require_iv(iv_des_t, 8,  "DES")
        iv_3des = require_iv(iv_3des_t, 8, "3DES")
        iv_aes  = require_iv(iv_aes_t, 16, "AES-256")

        # DES
        ct_des = cifrar_des(k_des, iv_des, texto)
        pt_des = descifrar_des(k_des, iv_des, ct_des)
        imprimir_resultado("DES", k_des, act_des, iv_des, ct_des, pt_des)

        # 3DES
        ct_3des = cifrar_3des(k_3des, iv_3des, texto)
        pt_3des = descifrar_3des(k_3des, iv_3des, ct_3des)
        imprimir_resultado("3DES", k_3des, act_3des, iv_3des, ct_3des, pt_3des)

        # AES-256
        ct_aes = cifrar_aes(k_aes, iv_aes, texto)
        pt_aes = descifrar_aes(k_aes, iv_aes, ct_aes)
        imprimir_resultado("AES-256", k_aes, act_aes, iv_aes, ct_aes, pt_aes)

    except Exception as e:
        print(f"\nError: {e}")
