from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generar_clave_aes(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password)

def cifrar_archivo_AES(archivo_entrada, archivo_salida, password):
    salt = os.urandom(16)
    clave_aes = generar_clave_aes(password, salt)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(clave_aes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(archivo_entrada, 'rb') as f:
        contenido = f.read()

    contenido_cifrado = encryptor.update(contenido) + encryptor.finalize()

    with open(archivo_salida, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(contenido_cifrado)

    print(f"Archivo cifrado guardado en '{archivo_salida}'.")

def descifrar_archivo_AES(archivo_cifrado, archivo_salida, password):
    with open(archivo_cifrado, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        contenido_cifrado = f.read()

    clave_aes = generar_clave_aes(password, salt)

    cipher = Cipher(algorithms.AES(clave_aes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    contenido_descifrado = decryptor.update(contenido_cifrado) + decryptor.finalize()

    with open(archivo_salida, 'wb') as f:
        f.write(contenido_descifrado)

    print(f"Archivo descifrado guardado en '{archivo_salida}'.")


password = b'dsfsdfsdjfasdfd'
archivo_original = 'archivo.txt'
archivo_cifrado = 'archivo_cifrado_aes.bin'
archivo_descifrado = 'archivo_descifrado.txt'

cifrar_archivo_AES(archivo_original, archivo_cifrado, password)
descifrar_archivo_AES(archivo_cifrado, archivo_descifrado, password)
