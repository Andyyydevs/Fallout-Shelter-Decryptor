import base64
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def get_vector_bytes():
    return b"tu89geji340t89u2"

def get_passphrase_bytes(passphrase, vector_bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=vector_bytes,
        iterations=1000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt(plain_text, pass_phrase):
    vector_bytes = get_vector_bytes()
    passphrase_bytes = get_passphrase_bytes(pass_phrase, vector_bytes)
    
    cipher = Cipher(algorithms.AES(passphrase_bytes), modes.CBC(vector_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to be a multiple of 16 bytes
    padded_text = plain_text.encode('utf-8')
    padding_length = 16 - (len(padded_text) % 16)
    padded_text += bytes([padding_length] * padding_length)
    
    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

def encrypt_and_save_to_file(input_file_path, output_file_path, pass_phrase):
    try:
        with open(input_file_path, 'r') as file:
            json_data = json.load(file)
        
        json_string = json.dumps(json_data, indent=2)
        encrypted_text = encrypt(json_string, pass_phrase)
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        with open(output_file_path, 'w') as file:
            file.write(encrypted_text)
        
        print(f'Encrypted data saved to {output_file_path}')
    except FileNotFoundError:
        print(f"Error: File not found - {input_file_path}")
    except json.JSONDecodeError:
        print("Error: Input file is not valid JSON")
    except Exception as e:
        print(f"Error during encryption or file handling: {str(e)}")

if __name__ == "__main__":
    input_file_path = 'DecryptedSave.json'  # Replace with your input JSON file path
    output_file_path = './Edited/Vault1.sav'  # Replace with your desired output file path
    pass_phrase = 'UGxheWVy'  # Replace with your passphrase
    encrypt_and_save_to_file(input_file_path, output_file_path, pass_phrase)