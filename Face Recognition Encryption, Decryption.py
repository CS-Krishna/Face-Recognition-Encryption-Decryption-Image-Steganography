import face_recognition # A library for face recognition.
import os # Provides a way to interact with the operating system, such as reading or writing files.
import sys # Provides access to some variables used or maintained by the Python interpreter.
import base64 # Handles encoding and decoding data using base64.
from cryptography.fernet import Fernet # A symmetric encryption algorithm for securing data.
from cryptography.hazmat.primitives import hashes # Used for password-based key derivation.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Used for password-based key derivation.
import tkinter as tk # Python's standard GUI (Graphical User Interface) package.
from tkinter import filedialog # Provides dialogs for file selection.
import shutil # Offers a higher-level interface for file operations.
import cv2 # OpenCV library for computer vision tasks.
from PIL import Image # Python Imaging Library for image processing.
import numpy as np # A library for numerical operations on arrays.
from tkinter import messagebox # Part of tkinter for creating message boxes.
from tkinter import *
import pyAesCrypt # A library for AES encryption.
import hashlib # Provides hash functions.
import tkinter.filedialog as filedialog
import io # A core Python module for handling streams.
from PIL import Image, ImageTk # A module to display images in the tkinter GUI.
import binascii

# Function to generate a key from a password and salt
def generate_key(password, salt):
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Function to encrypt files in a folder using a given key
def encrypt_folder(directory_path, key):
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    # Create a cipher object with the key
    cipher_suite = Fernet(key)
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                file_data = file.read()
            encrypted_data = cipher_suite.encrypt(file_data)
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)
    info_page = tk.Tk()
    info_page.title("Info") # Set the title of the window
    info_page.geometry("400x300") # Set the size of the window
    # Create and display a title label
    title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
    title.pack(pady=20)
    # Create and display a description label with word wrapping
    desc = tk.Label(info_page, text="Folder Encrypted successfully ", wraplength=300)
    desc.pack()

# Function to decrypt files in a folder using a given key (linked with face_recognition_folder)
def decrypt_folder_face(directory_path, key):
    face_recognition_folder(directory_path, key)

# Function to decrypt files in a folder using a given key
def decrypt_folder(directory_path, key):
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    # Create a cipher object with the key
    cipher_suite = Fernet(key)
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(file_path, 'wb') as file:
                file.write(decrypted_data)
    info_page = tk.Tk()
    info_page.title("Info") # Set the title of the window
    info_page.geometry("400x300") # Set the size of the window
    # Create and display a title label
    title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
    title.pack(pady=20)
    # Create and display a description label with word wrapping
    desc = tk.Label(info_page, text="Face Recognized ", wraplength=300)
    desc.pack()
    desc = tk.Label(info_page, text="Folder decrypted successfully ", wraplength=300)
    desc.pack()

# Function to convert data into 8-bit binary form using ASCII value of characters
def genData(data):
    # List of binary codes of given data
    newd = []
    for i in data:
        newd.append(format(ord(i), '08b'))
    return newd

# Function to modify pixels according to the 8-bit binary data and return the result
def modPix(pix, data):
    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):
        # Extracting 3 pixels at a time
        pix = [value for value in imdata.__next__()[:3] +
                                imdata.__next__()[:3] +
                                imdata.__next__()[:3]]
        # Pixel value should be made odd for 1 and even for 0
        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j] % 2 != 0):
                pix[j] -= 1
            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if(pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1
        # Eighth pixel of every set tells whether to stop or read further.
        # 0 means keep reading; 1 means the message is over.
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                if(pix[-1] != 0):
                    pix[-1] -= 1
                else:
                    pix[-1] += 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1
        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data):
	#binary_data = ''.join(format(ord(char), '08b') for char in data)
	w = newimg.size[0]
	(x, y) = (0, 0)
	for pixel in modPix(newimg.getdata(), data):
        # Putting modified pixels in the new image
		newimg.putpixel((x, y), pixel)
		if (x == w - 1):
			x = 0
			y += 1
		else:
			x += 1

input_entry_2 = ""
# Function to encode data into an image (linked with face_recognition_image)
def encode_image(chosen_image):
    global input_entry_2  # Declare input_entry_2 as a global variable
    image = Image.open(chosen_image)
    info_page = tk.Tk()
    info_page.title("Info")  # Set the title of the window
    info_page.geometry("400x300")  # Set the size of the window
    # Create and display a title label
    title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
    title.pack(pady=20)

    input_label = tk.Label(info_page, text="Enter your secret data:")
    input_label.pack()
    input_entry = tk.Entry(info_page)
    input_entry.pack()

    def encode_with_data():
        global input_entry_2  # Access the global variable
        data = input_entry.get()
        if len(data) == 0:
            desc = tk.Label(info_page, text="Please enter some data", wraplength=300)
            desc.pack()
        else:
            newimg = image.copy()
            encode_enc(newimg, data)
            input_label_2 = tk.Label(info_page, text="Enter the name of the new image (with extension): ")
            input_label_2.pack()
            input_entry_2 = tk.Entry(info_page)  # Define input_entry_2 as a global variable
            input_entry_2.pack()

            def save_encoded_image():
                new_img_name = input_entry_2.get()
                if "." not in new_img_name:
                    desc = tk.Label(info_page, text="Please enter a filename with an extension (e.g., 'myimage.png')",wraplength=300)
                    desc.pack()
                else:
                    newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))
                    desc = tk.Label(info_page, text="Image Encoded successfully!", wraplength=300)
                    desc.pack()

            save_button = tk.Button(info_page, text="Save Encoded Image", command=save_encoded_image)
            save_button.pack()

    encode_button = tk.Button(info_page, text="Encode Image", command=encode_with_data)
    encode_button.pack()

    info_page.mainloop()

# Function to decode data from an image
def decode_image(chosen_image):
    image = Image.open(chosen_image)
    data = ''
    imgdata = iter(image.getdata())
    while (True):
        pixels = [value for value in imgdata.__next__()[:3] +
                                imgdata.__next__()[:3] +
                                imgdata.__next__()[:3]]
        # String of binary data
        binstr = ''
        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'
        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0):
            return data


# Function for face recognition on a folder
def face_recognition_folder(directory_path, key):
    # Load face encoding and name
    face_encoding = []
    face_name = []

    # Load faces
    img1 = face_recognition.load_image_file(r"C:\Users\Krishna Sachdeva\Pictures\Camera Roll\My Photo.jpg")
    img2 = face_recognition.load_image_file(r"C:\Users\Krishna Sachdeva\Pictures\Camera Roll\Train\Train photo 1.jpg")
    img3 = face_recognition.load_image_file(r"C:\Users\Krishna Sachdeva\Pictures\Camera Roll\Train\Train photo 2.jpg")

    img1_encoding = face_recognition.face_encodings(img1)[0]
    img2_encoding = face_recognition.face_encodings(img2)[0]
    img3_encoding = face_recognition.face_encodings(img3)[0]

    face_encoding.extend([img1_encoding, img2_encoding, img3_encoding])
    face_name.extend(["Krishna", "Krishna", "Krishna"]) # Add more face names if needed

    # Webcam initialize
    web = cv2.VideoCapture(0)
    while True:
        _, frame = web.read()
        # Find all faces
        face_loc = face_recognition.face_locations(frame)
        face_encod_frame = face_recognition.face_encodings(frame)
        # Loop for found faces
        for (top, right, bottom, left), face_encod in zip(face_loc, face_encod_frame):
            matches = face_recognition.compare_faces(face_encoding, face_encod)
            name = 'Unknown'
        if True in matches:
            first_match = matches.index(True)
            name = face_name[first_match]
            decrypt_folder(directory_path, key)
            break
        else:
            info_page = tk.Tk()
            info_page.title("Info") # Set the title of the window
            info_page.geometry("400x300") # Set the size of the window
            # Create and display a title label
            title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
            title.pack(pady=20)
            # Create and display a description label with word wrapping
            desc = tk.Label(info_page, text="Face Not Recognized!", wraplength=300)
            desc.pack()
            break

# Function for face recognition on an image
def face_recognition_image(chosen_image):
    # Load face encoding and name
    face_encoding = []
    face_name = []

    # Load faces
    img1 = face_recognition.load_image_file(r"C:\Users\Krishna Sachdeva\Pictures\Camera Roll\My Photo.jpg")
    img2 = face_recognition.load_image_file(r"C:\Users\Krishna Sachdeva\Pictures\Camera Roll\Train\Train photo 1.jpg")
    img3 = face_recognition.load_image_file(r"C:\Users\Krishna Sachdeva\Pictures\Camera Roll\Train\Train photo 2.jpg")

    img1_encoding = face_recognition.face_encodings(img1)[0]
    img2_encoding = face_recognition.face_encodings(img2)[0]
    img3_encoding = face_recognition.face_encodings(img3)[0]

    face_encoding.extend([img1_encoding, img2_encoding, img3_encoding])
    face_name.extend(["Krishna", "Krishna", "Krishna"]) # Add more face names if needed

    # Webcam initialize
    web = cv2.VideoCapture(0)
    while True:
        _, frame = web.read()
        # Find all faces
        face_loc = face_recognition.face_locations(frame)
        face_encod_frame = face_recognition.face_encodings(frame)
        # Loop for found faces
        for (top, right, bottom, left), face_encod in zip(face_loc, face_encod_frame):
            matches = face_recognition.compare_faces(face_encoding, face_encod)
            name = 'Unknown'
        if True in matches:
            print("")
            first_match = matches.index(True)
            name = face_name[first_match]
            #print("Decoded Word : " + decode_image(chosen_image))
            info_page = tk.Tk()
            info_page.title("Info") # Set the title of the window
            info_page.geometry("400x300") # Set the size of the window
            # Create and display a title label
            title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
            title.pack(pady=20)
            # Create and display a description label with word wrapping
            desc = tk.Label(info_page, text="Face Recognized ", wraplength=300)
            desc.pack()
            desc = tk.Label(info_page, text="Decoded Word: "+ decode_image(chosen_image), font=(15), wraplength=300)
            desc.pack()
            desc = tk.Label(info_page, text="Image Decoded successfully.", wraplength=300)
            desc.pack()
            break
        else:
            info_page = tk.Tk()
            info_page.title("Info") # Set the title of the window
            info_page.geometry("400x300") # Set the size of the window
            # Create and display a title label
            title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
            title.pack(pady=20)
            # Create and display a description label with word wrapping
            desc = tk.Label(info_page, text="Face Not Recognized!", wraplength=300)
            desc.pack()
            break

def show_info(directory_path, key):
    # Create a new Tkinter window
    info_page = tk.Tk()
    info_page.title("Info") # Set the title of the window
    info_page.geometry("400x300") # Set the size of the window

    # Create and display a title label
    title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
    title.pack(pady=20)

    # Create and display a description label with word wrapping
    desc = tk.Label(info_page, text="A platform for secure storage and retrieval of your important files.", wraplength=300)
    desc.pack()

    # Create and display a label for options with a larger font size
    options = tk.Label(info_page, text="Options:", font=("Arial", 15))
    options.pack(pady=20)

    # Create a frame to organize buttons
    grid = Frame(info_page)
    grid.pack(padx=20, pady=20)

    # Create and display a button for encrypting a folder
    def choose_encrypt_folder():
        chosen_folder = filedialog.askdirectory()
        encrypt_folder(chosen_folder, key)
    encrypt_folder_button = tk.Button(grid, text="Encrypt Folder", command=choose_encrypt_folder)
    encrypt_folder_button.grid(row=0, column=0, padx=5, pady=5)

    def face_message_folder():
        info_page = tk.Tk()
        info_page.title("Info") # Set the title of the window
        info_page.geometry("400x300") # Set the size of the window
        # Create and display a title label
        title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
        title.pack(pady=20)
        # Create and display a description label with word wrapping
        desc = tk.Label(info_page, text="Please Wait! ", wraplength=300)
        desc.pack()
        desc = tk.Label(info_page, text="Turning Camera On for Face Recognition", wraplength=300)
        desc.pack()
        choose_decrypt_folder()
        

    # Create and display a button for decrypting a folder
    def choose_decrypt_folder():
        chosen_folder = filedialog.askdirectory()
        decrypt_folder_face(chosen_folder, key)
    decrypt_folder_button = tk.Button(grid, text="Decrypt Folder", command=face_message_folder)
    decrypt_folder_button.grid(row=0, column=1, padx=5, pady=5, columnspan=10)

 # Create and display a button for encoding an image
    def choose_encode_image():
        chosen_image = filedialog.askopenfilename()
        encode_image(chosen_image)
    encode_button = tk.Button(grid, text="Encode Image", command=choose_encode_image)
    encode_button.grid(row=1, column=0, padx=5, pady=5)

    def face_message_image():
        info_page = tk.Tk()
        info_page.title("Info") # Set the title of the window
        info_page.geometry("400x300") # Set the size of the window
        # Create and display a title label
        title = tk.Label(info_page, text="SecureBox", font=("Arial", 20))
        title.pack(pady=20)
        # Create and display a description label with word wrapping
        desc = tk.Label(info_page, text="Please Wait! ", wraplength=300)
        desc.pack()
        desc = tk.Label(info_page, text="Turning Camera On for Face Recognition", wraplength=300)
        desc.pack()
        choose_decode_image()

# Create and display a button for decoding an image
    def choose_decode_image():
        chosen_image = filedialog.askopenfilename()
        face_recognition_image(chosen_image)
    decode_button = tk.Button(grid, text="Decode Image", command=face_message_image)
    decode_button.grid(row=1, column=1, padx=5, pady=5)

    # Create and display a button for logging out
    logout_button = tk.Button(grid, text="Logout", command=info_page.destroy)
    logout_button.grid(row=1, column=2, padx=5, pady=5, columnspan=2)

    # Start the Tkinter event loop
    info_page.mainloop()

def main():
    # Set the directory path, password, and generate a key
    directory_path = ""
    password = "09October2004"
    salt = os.urandom(16)
    key = generate_key(password, salt)

    # Show the main info page with buttons
    show_info(directory_path, key)

if __name__ == "__main__":
    # Run the main function when the script is executed
    main()
