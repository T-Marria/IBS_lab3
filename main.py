##Вариант 2
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
import os
import json
from tqdm import tqdm
import argparse
import pickle

settings = {
    'initial_file': "sad.txt",  # Файл с текстом
    'encrypted_file': 'encrypted_file.txt',  # Зашифрованный текст
    'decrypted_file': 'decrypted_file.txt',  # Дешиврованный текст
    'symmetric_key': 'symmetric_key.txt',  # Симметричный ключ Camellia
    'public_key': 'public_key.pem',  # Открытый ключ RSA
    'secret_key': 'secret_key.pem',  # закрытый ключ RSA
}


def input_len_key() -> int:
    """
        Функция возвращает длину ключа для алгоритма Camellia
    """
    print("Choose key length:\n"
          "1: 128\n"
          "2: 192\n"
          "3: 256\n"
          "Make a decision. ")
    klen = input()
    if int(klen) == 1:
        return int(128)
    if int(klen) == 2:
        return int(192)
    if int(klen) == 3:
        return int(256)


def generate_key(encrypted_symmetric_key: str, public_key_path: str, secret_key_path: str, len_key: int) -> None:
    symmetrical_key = algorithms.Camellia(os.urandom(int(len_key / 8)))
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    with open(public_key_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(secret_key_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    encrypt_symmetrical_key = public_key.encrypt(symmetrical_key.key,
                                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(),
                                                              label=None))

    with open(encrypted_symmetric_key, 'wb') as summetric_out:
        summetric_out.write(encrypt_symmetrical_key)


def encrypt_data(text_file: str, secret_key_path: str, encrypted_symmetric_key_path: str,
                 encrypted_text_file_path: str):
    """
        Функция шифрует текст симметричным алгоритмом Camellia из файла по указанному пути, ключ симметричного алгоритма
        шифрования зашифрован ассиметричным алгоритмом RSA, поэтому предварительно ключ расшифровывается при помощи
        закрытого ключа RSA. Зашифрованный текст сохраняется в файл
        :param: text_file: Путь к файлу с текстом
        :param: secret_key_path: Путь к закрытому ключу ассиметричного шифра
        :param: encrypted_symmetric_key_path: Путь к зашифрованному ключу симметричного алгоритма Camellia
        :param: encrypted_text_file_path: Путь сохранения зашифрованного текста
        :return: None
    """
    with open(encrypted_symmetric_key_path, "rb") as file:
        encrypted_symmetric_key = file.read()
    with open(secret_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    with open(text_file, "r", encoding='UTF-8') as file:
        data = file.read()
    pad = padding2.ANSIX923(32).padder()
    text = bytes(data, 'UTF-8')
    padded_text = pad.update(text) + pad.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(decrypted_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)
    encrypted_data = {"encrypted_text": c_text, "iv": iv}
    with open(encrypted_text_file_path, "wb") as file:
        pickle.dump(encrypted_data, file)


def decrypt_data(encrypted_text_file_path: str, secret_key_path: str, encrypted_symmetric_key_path: str,
                 decrypted_text_file_path: str):
    """
           Функция расшифровывает текст из указанного файла, предварительно расшифровывает ключ симметричного алгоритма,
           который был зашифрован ассиметричным алгоритмом RSA при помощи закрытого ключа
           :param: encrypted_text_file_path: Путь к зашифрованному тексту
           :param: secret_key_path: Путь к закрытому ключу ассиметричного шифра
           :param: encrypted_symmetric_key_path: Путь к зашифрованному ключу симметричного алгоритма шифрования
           :param: decrypted_text_file_path: Путь к расшифрованному тексту
           :return: None
       """
    with open(encrypted_symmetric_key_path, "rb") as file:
        encrypted_symmetric_key = file.read()
    with open(secret_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    with open(encrypted_text_file_path, 'rb') as file:
        encrypted_text = pickle.load(file)
    text = encrypted_text['encrypted_text']
    iv = encrypted_text['iv']
    cipher = Cipher(algorithms.Camellia(decrypted_symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(8).unpadder()
    unpadded_dc_data = unpadder.update(decrypted_text)
    final_text = unpadded_dc_data.decode('UTF-8')
    with open(decrypted_text_file_path, 'w', encoding='UTF-8') as file:
        file.write(final_text)


parser = argparse.ArgumentParser(description='main.py')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
args = parser.parse_args()
with open('settings.json') as json_file:
    json_data = json.load(json_file)
if args.generation is not None:
    len_key = input_len_key()
    generate_key(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'], len_key)
    print('Key length: ' + str(len_key))
if args.encryption is not None:
    with tqdm(100, desc='Encrypting your file: ') as progressbar:
        encrypt_data(json_data['initial_file'], json_data['secret_key'], json_data['symmetric_key'],
                     json_data['encrypted_file'])
        progressbar.update(100)
        print('\n Encryption successful.\n')
if args.decryption is not None:
    with tqdm(100, desc='Decrypting your file: ') as progressbar:
        decrypt_data(json_data['encrypted_file'], json_data['secret_key'], json_data['symmetric_key'],
                     json_data['decrypted_file'])
        progressbar.update(100)
        print('\n Decryption successful.\n')
