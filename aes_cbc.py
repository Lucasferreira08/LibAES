#!/usr/bin/env python3
"""
Cifra e decifra arquivos de qualquer formato usando AES em modo CBC.

A chave AES (128/192/256 bits) é derivada da senha informada pelo usuário
com PBKDF2-HMAC-SHA256 + salt aleatório. A integridade do arquivo cifrado é
garantida por um HMAC-SHA256 (Encrypt-then-MAC), o que também permite
detectar senha incorreta antes de tentar decifrar.

Formato do arquivo cifrado:
    MAGIC(4) | tam. chave em bytes(1) | iterações(4) | salt(16) | IV(16) | ciphertext | HMAC(32)
"""

import argparse
import getpass
import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"AESC"
SALT_LEN = 16
IV_LEN = 16           # bloco AES = 128 bits
MAC_LEN = 32          # HMAC-SHA256
ITERATIONS = 600_000  # recomendação OWASP (2023+) para PBKDF2-HMAC-SHA256
HEADER_FMT = ">4sBI"  # magic, tamanho da chave em bytes, iterações
HEADER_LEN = struct.calcsize(HEADER_FMT)


def derive_keys(password: str, salt: bytes, bits: int, iterations: int):
    """Deriva a chave AES e a chave do HMAC a partir da senha (PBKDF2)."""
    enc_len = bits // 8
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=enc_len + 32
    )
    return material[:enc_len], material[enc_len:]


def encrypt(data: bytes, password: str, bits: int) -> bytes:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    enc_key, mac_key = derive_keys(password, salt, bits, ITERATIONS)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    header = struct.pack(HEADER_FMT, MAGIC, bits // 8, ITERATIONS)
    body = header + salt + iv + ciphertext
    tag = hmac.new(mac_key, body, hashlib.sha256).digest()
    return body + tag


def decrypt(blob: bytes, password: str) -> bytes:
    min_len = HEADER_LEN + SALT_LEN + IV_LEN + 16 + MAC_LEN
    if len(blob) < min_len:
        raise ValueError("arquivo muito pequeno para ser um arquivo cifrado válido")

    magic, key_len, iterations = struct.unpack(HEADER_FMT, blob[:HEADER_LEN])
    bits = key_len * 8
    if magic != MAGIC:
        raise ValueError("arquivo não foi gerado por este programa (cabeçalho inválido)")
    if bits not in (128, 192, 256):
        raise ValueError(f"tamanho de chave inválido no cabeçalho: {bits}")

    pos = HEADER_LEN
    salt = blob[pos:pos + SALT_LEN]; pos += SALT_LEN
    iv = blob[pos:pos + IV_LEN]; pos += IV_LEN
    ciphertext = blob[pos:-MAC_LEN]
    tag = blob[-MAC_LEN:]

    enc_key, mac_key = derive_keys(password, salt, bits, iterations)
    expected = hmac.new(mac_key, blob[:-MAC_LEN], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("senha incorreta ou arquivo corrompido/adulterado")

    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def default_output(path: str, mode: str) -> str:
    if mode == "cifrar":
        return path + ".enc"
    if path.endswith(".enc"):
        return path[:-4]
    return path + ".dec"


def ask_mode() -> str:
    print("Escolha a operação:")
    print("  1) Cifrar")
    print("  2) Decifrar")
    while True:
        choice = input("> ").strip().lower()
        if choice in ("1", "c", "cifrar"):
            return "cifrar"
        if choice in ("2", "d", "decifrar"):
            return "decifrar"
        print("Opção inválida. Digite 1 ou 2.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cifra/decifra arquivos com AES-CBC (chave derivada via PBKDF2)."
    )
    parser.add_argument("arquivo", help="caminho do arquivo de entrada")
    parser.add_argument("chave", nargs="?",
                        help="senha/chave em texto (se omitida, será solicitada sem eco)")
    parser.add_argument("-m", "--modo", choices=["cifrar", "decifrar"],
                        help="operação; se omitida, um menu será exibido")
    parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256,
                        help="tamanho da chave AES ao cifrar (padrão: 256)")
    parser.add_argument("-o", "--saida",
                        help="arquivo de saída (padrão: <arquivo>.enc ao cifrar, "
                             "remove .enc ao decifrar)")
    parser.add_argument("-f", "--forcar", action="store_true",
                        help="sobrescrever o arquivo de saída se já existir")
    args = parser.parse_args()

    mode = args.modo or ask_mode()
    password = args.chave if args.chave is not None else getpass.getpass("Chave: ")
    if not password:
        print("Erro: a chave não pode ser vazia.", file=sys.stderr)
        return 1

    if not os.path.isfile(args.arquivo):
        print(f"Erro: arquivo não encontrado: {args.arquivo}", file=sys.stderr)
        return 1

    out_path = args.saida or default_output(args.arquivo, mode)
    if os.path.exists(out_path) and not args.forcar:
        print(f"Erro: '{out_path}' já existe (use -f para sobrescrever).", file=sys.stderr)
        return 1

    with open(args.arquivo, "rb") as f:
        data = f.read()

    try:
        if mode == "cifrar":
            result = encrypt(data, password, args.bits)
        else:
            result = decrypt(data, password)
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1

    with open(out_path, "wb") as f:
        f.write(result)

    acao = "cifrado" if mode == "cifrar" else "decifrado"
    print(f"Arquivo {acao} com sucesso: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
