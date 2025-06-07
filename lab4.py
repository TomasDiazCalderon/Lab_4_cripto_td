from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


ALGORITHMS_CONFIG = {
    'AES-256': {'block_size': 16, 'key_size': 32, 'cipher': AES},
    '3DES':    {'block_size': 8,  'key_size': 16, 'cipher': DES3},
    'DES':     {'block_size': 8,  'key_size': 8,  'cipher': DES}
}

def adjust_input(data_bytes, required_size):
    """
    Ajusta una clave o IV al tamaño requerido con relleno aleatorio.
    """
    current_size = len(data_bytes)
    if current_size < required_size:
        padding = get_random_bytes(required_size - current_size)
        return data_bytes + padding
    elif current_size > required_size:
        return data_bytes[:required_size]
    return data_bytes


def encrypt(algorithm_name, key_bytes, iv_bytes, plaintext_bytes):
    """
    Cifra los datos usando el algoritmo, clave e IV especificados.
    Devuelve solo el texto cifrado en bytes.
    """
    config = ALGORITHMS_CONFIG[algorithm_name]
    cipher_class = config['cipher']
    block_size = config['block_size']

    cipher = cipher_class.new(key_bytes, cipher_class.MODE_CBC, iv_bytes)
    padded_text = pad(plaintext_bytes, block_size, style='pkcs7')
    cipher_text = cipher.encrypt(padded_text)
    return cipher_text


def decrypt(algorithm_name, key_bytes, iv_bytes, ciphertext_bytes):
    """
    Descifra los datos usando el algoritmo, clave e IV especificados.
    Devuelve el texto original en bytes.
    """
    config = ALGORITHMS_CONFIG[algorithm_name]
    cipher_class = config['cipher']
    block_size = config['block_size']

    decipher = cipher_class.new(key_bytes, cipher_class.MODE_CBC, iv_bytes)
    decrypted_padded_text = decipher.decrypt(ciphertext_bytes)
    original_text_bytes = unpad(decrypted_padded_text, block_size)
    return original_text_bytes



if __name__ == "__main__":
    
    user_key = input("Ingresa la clave (será usada para todos los algoritmos): ")
    user_iv = input("Ingresa el Vector de Inicialización (IV): ")
    user_text = input("Ingresa el texto a cifrar: ")

    
    for algo_name in ALGORITHMS_CONFIG:
        print(f"\n" + "="*50)
        print(f"{algo_name}")
        print("="*50)

        # Se preparan los datos
        config = ALGORITHMS_CONFIG[algo_name]
        key_size = config['key_size']
        
        key_bytes_input = user_key.encode('utf-8')
        iv_bytes_input = user_iv.encode('utf-8')
        text_bytes_input = user_text.encode('utf-8')

        final_key = adjust_input(key_bytes_input, key_size)
        final_iv = adjust_input(iv_bytes_input, config['block_size'])

        
        
        print(f"Clave final utilizada (bytes): {final_key}")
        print(f"Clave final (Base64): {base64.b64encode(final_key).decode('ascii')}")
        print(f"IV final utilizado (bytes):   {final_iv}")
        print(f"IV final (Base64):   {base64.b64encode(final_iv).decode('ascii')}")
        # -----------------------------------
        
        # Proceso de Cifrado
        ciphertext = encrypt(algo_name, final_key, final_iv, text_bytes_input)
        print(f"\nTexto cifrado (hex): {ciphertext.hex()}")

        # Proceso de Descifrado
        decrypted_bytes = decrypt(algo_name, final_key, final_iv, ciphertext)
        
        decrypted_text = decrypted_bytes.decode('utf-8')
        print(f"Texto descifrado: {decrypted_text}")
        print("="*50 + "\n")