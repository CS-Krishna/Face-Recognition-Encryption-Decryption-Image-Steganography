from cryptography.fernet import Fernet

# Generate a key and create a cipher object
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Save the key to a file
with open("key.key", "wb") as key_file:
    key_file.write(key)