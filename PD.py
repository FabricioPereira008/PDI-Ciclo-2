import cv2
import numpy as np
from PIL import Image
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from io import BytesIO
import base64

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def gerar_hash(image_path):
    with open(image_path, "rb") as file:
        file_data = file.read()
        return hashlib.sha256(file_data).hexdigest()

def embutir_texto(image_path, texto, output_path):
    texto += "####EOF####"
    image = cv2.imread(image_path)
    binary_text = ''.join(format(ord(i), '08b') for i in texto)
    binary_index = 0
    for row in image:
        for pixel in row:
            for color in range(3):
                if binary_index < len(binary_text):
                    pixel[color] = int(format(pixel[color], '08b')[:-1] + binary_text[binary_index], 2)
                    binary_index += 1
                if binary_index >= len(binary_text):
                    break
    cv2.imwrite(output_path, image)

def recuperar_texto(image_path):
    image = cv2.imread(image_path)
    binary_text = ""
    for row in image:
        for pixel in row:
            for color in range(3):
                binary_text += format(pixel[color], '08b')[-1]
    byte_array = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    decoded_text = ''.join(chr(int(b, 2)) for b in byte_array if int(b, 2) != 0)

    if "####EOF####" in decoded_text:
        decoded_text = decoded_text.split("####EOF####")[0]
    else:
        decoded_text = "[Erro] Marcador de fim não encontrado."

    return decoded_text


def encriptar_mensagem(mensagem):
    encrypted = public_key.encrypt(
        mensagem.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

def decriptar_mensagem(mensagem_encriptada):
    decrypted = private_key.decrypt(
        base64.b64decode(mensagem_encriptada.encode()),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode()

def exibir_menu():
    while True:
        print("\n--- Menu de Opções ---")
        print("(1) Embutir texto em uma imagem")
        print("(2) Recuperar texto de uma imagem")
        print("(3) Gerar hash das imagens original e alterada")
        print("(4) Encriptar mensagem usando chave pública/privada")
        print("(5) Decriptar mensagem encriptada")
        print("(S ou s) Sair")
        opcao = input("Escolha uma opção: ")

        if opcao == '1':
            image_path = input("Caminho da imagem original: ")
            texto = input("Digite o texto para embutir: ")
            output_path = input("Caminho para salvar a imagem com texto embutido: ")
            embutir_texto(image_path, texto, output_path)
            print(f"Texto embutido com sucesso na imagem {output_path}.")

        elif opcao == '2':
            image_path = input("Caminho da imagem com texto embutido: ")
            texto_recuperado = recuperar_texto(image_path)
            print(f"Texto recuperado: {texto_recuperado}")

        elif opcao == '3':
            original_path = input("Caminho da imagem original: ")
            altered_path = input("Caminho da imagem alterada: ")
            hash_original = gerar_hash(original_path)
            hash_altered = gerar_hash(altered_path)
            print(f"Hash da imagem original: {hash_original}")
            print(f"Hash da imagem alterada: {hash_altered}")
            if hash_original == hash_altered:
                print("As imagens são idênticas (sem alteração).")
            else:
                print("As imagens são diferentes (alteração detectada).")

        elif opcao == '4':
            mensagem = input("Digite a mensagem para encriptar: ")
            mensagem_encriptada = encriptar_mensagem(mensagem)
            print(f"Mensagem encriptada: {mensagem_encriptada}")

        elif opcao == '5':
            mensagem_encriptada = input("Digite a mensagem encriptada: ")
            try:
                mensagem_decriptada = decriptar_mensagem(mensagem_encriptada)
                print(f"Mensagem decriptada: {mensagem_decriptada}")
            except Exception as e:
                print("Falha na decriptação. Verifique se a mensagem está correta e tente novamente.")

        elif opcao.lower() == 's':
            print("Encerrando aplicação.")
            break
        else:
            print("Opção inválida. Tente novamente.")

exibir_menu()
