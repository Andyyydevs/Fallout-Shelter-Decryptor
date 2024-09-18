import base64
import json
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

def decrypt(cipher_text, pass_phrase):
    vector_bytes = get_vector_bytes()
    buffer = base64.b64decode(cipher_text)
    passphrase_bytes = get_passphrase_bytes(pass_phrase, vector_bytes)
    
    cipher = Cipher(algorithms.AES(passphrase_bytes), modes.CBC(vector_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(buffer) + decryptor.finalize()
    
    # Remove padding
    unpadded = decrypted.rstrip(b'\0')
    return unpadded.decode('utf-8')

def decrypt_and_save_to_file(input_file_path, output_file_path, pass_phrase):
    try:
        with open(input_file_path, 'r') as file:
            data = file.read()
        
        decrypted_text = decrypt(data, pass_phrase)
        json_data = json.loads(decrypted_text)
        
        with open(output_file_path, 'w') as file:
            json.dump(json_data, file, indent=2)
        
        print(f'Decrypted data saved to {output_file_path}')
    except FileNotFoundError:
        print(f"Error: File not found - {input_file_path}")
    except json.JSONDecodeError:
        print("Error: Decrypted data is not valid JSON")
    except Exception as e:
        print(f"Error during decryption or file handling: {str(e)}")

if __name__ == "__main__":
    input_file_path = 'Vault1.sav'  # Replace with your input file path
    output_file_path = 'DecryptedSave.json'  # Replace with your desired output JSON file path
    pass_phrase = 'UGxheWVy'
    decrypt_and_save_to_file(input_file_path, output_file_path, pass_phrase)