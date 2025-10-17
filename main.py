from fastapi import FastAPI, Request
from pydantic import BaseModel
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
import base64

app = FastAPI()

# Modelo de datos del usuario
class Usuario(BaseModel):
    TipoDocumento: str
    Documento: str
    Nombres: str
    Apellidos: str
    Direccion: str
    Correo: str
    FechaNacimiento: str
    Nacionalidad: str
    Usuario: str
    Clave: str
    CuentaAhorros: str
    ClaveCA: str
    TarjetaCredito: str
    FechaVencimiento: str
    CVV: str

# Cifrado de transporte
def encode_base64(text): return base64.b64encode(text.encode()).decode()
def encode_ascii(text): return ' '.join(str(ord(c)) for c in text)
def encode_binary(text): return ' '.join(format(ord(c), '08b') for c in text)
def encode_decimal(text): return ' '.join(str(ord(c)) for c in text)
def encode_hex(text): return text.encode().hex()
def encode_octal(text): return ' '.join(format(ord(c), 'o') for c in text)

# Padding para cifrado por bloques
def pad(text, block_size):
    padding_len = block_size - len(text) % block_size
    return text + chr(padding_len) * padding_len
# Cifrado en reposo/uso
def encrypt_aes(text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(text, AES.block_size)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def encrypt_des(text):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(text, DES.block_size)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def encrypt_3des(text):
    key = DES3.adjust_key_parity(get_random_bytes(24))
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = pad(text, DES3.block_size)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

@app.post("/cifrar")
async def cifrar_usuario(usuario: Usuario):
    data = usuario.dict()
    transporte = {}
    reposo_uso = {}

    for campo, valor in data.items():
        transporte[campo] = {
            "Base64": encode_base64(valor),
            "ASCII": encode_ascii(valor),
            "Binario": encode_binary(valor),
            "Decimal": encode_decimal(valor),
            "Hexadecimal": encode_hex(valor),
            "Octal": encode_octal(valor)
        }
        reposo_uso[campo] = {
            "AES": encrypt_aes(valor),
            "DES": encrypt_des(valor),
            "3DES": encrypt_3des(valor)
        }

    return {
        "Transporte": transporte,
        "Reposo_y_Uso": reposo_uso
    }