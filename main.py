from pyparsing import col
import streamlit as st
from PIL import Image
import base64
from io import BytesIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os

def encrypt_text(key_encrip, text):
    # key_encrip = key_encrip.encode('utf-8')
    text = text.encode('utf-8')

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Pad the text to be a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(text) + padder.finalize()

    # Create an AES cipher object with the key_encrip, mode, and backend
    cipher = Cipher(algorithms.AES(key_encrip), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded text
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()

    # Combine IV and ciphertext and encode in base64 for easy storage or transmission
    encrypted_data = b64encode(iv + ciphertext).decode('utf-8')

    return encrypted_data

def decrypt_text(key_decrip, encrypted_data):
    # key_decrip = key_decrip.encode('utf-8')
    encrypted_data = b64decode(encrypted_data)

    # Extract IV from the first 16 bytes of the encrypted data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Create an AES cipher object with the key_decrip, mode, and backend
    cipher = Cipher(algorithms.AES(key_decrip), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        # Decrypt the ciphertext
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8')

    except ValueError as e:
        print(f"Decryption error: {e}")
        return None  # or handle the error in another way

# Function to encode the message into the image
def encode_message(message, image):
    encoded_image = image.copy()

    # Encoding the message into the image
    encoded_image.putdata(encode_data(image, message))

    # Save the encoded image
    encoded_image_path = "encoded.png"
    encoded_image.save(encoded_image_path)

    col1.success("Image encoded successfully.")
    show_encoded_image(encoded_image_path)

# Function to decode the hidden message from the image
def decode_message(image):
    decoded_message = decode_data(image)
    
    new_decoded_message = decrypt_text(key_decrip, decoded_message)
    
    if new_decoded_message is not None:
        col3.write("Enkripsi Message: " + decoded_message)
        col3.write("Hidden Message: " + new_decoded_message)
    else:
        col3.error("Decryption failed. Invalid key or padding.")
    
    show_decoded_image(image)

# Function to display the decoded image in the UI
def show_decoded_image(decoded_image):
    col4.header("Decoded Image")
    col4.image(decoded_image, caption="Decoded Image", use_column_width=True)

# Function to encode the data (message) into the image
def encode_data(image, data):
    data = data + "$"  # Adding a delimiter to identify the end of the message
    data_bin = ''.join(format(ord(char), '08b') for char in data)

    pixels = list(image.getdata())
    encoded_pixels = []

    index = 0
    for pixel in pixels:
        if index < len(data_bin):
            red_pixel = pixel[0]
            new_pixel = (red_pixel & 254) | int(data_bin[index])
            encoded_pixels.append((new_pixel, pixel[1], pixel[2]))
            index += 1
        else:
            encoded_pixels.append(pixel)

    return encoded_pixels

# Function to decode the data (message) from the image
def decode_data(image):
    pixels = list(image.getdata())

    data_bin = ""
    for pixel in pixels:
        data_bin += bin(pixel[0])[-1]  # Extracting the least significant bit of the red channel

    data = ""
    for i in range(0, len(data_bin), 8):
        byte = data_bin[i:i + 8]
        data += chr(int(byte, 2))
        if data[-1] == "$":
            break

    return data[:-1]  # Removing the delimiter

# Function to display the encoded image in the UI and add a download button
def show_encoded_image(image_path):
    encoded_image = Image.open(image_path)

    

    buffered = BytesIO()
    encoded_image.save(buffered, format="PNG")

    img_str = base64.b64encode(buffered.getvalue()).decode()

    href = f'<a href="data:file/png;base64,{img_str}" download="{image_path}">Download Encoded Image</a>'

    col2.header("Encoded Image")
    col2.image(encoded_image, caption="Encoded Image", use_column_width=True)
    col2.markdown(href, unsafe_allow_html=True)

# Streamlit GUI setup
st.set_page_config(page_title="Image Steganography", page_icon=":shushing_face:", layout="wide")
st.title("Hide your secrets!!!🤫")

tab1, tab2= st.tabs(["Encode", "Decode"])
with tab1:
    col1, col2 = st.columns(2)

    col1.header("Encode")


    message = col1.text_input("Enter Message to Hide")
    key_encrip = col1.text_input("Enter Key Encode")

    # Convert the key to bytes using UTF-8 encoding
    key_encrip = key_encrip.encode('utf-8')

    # Choose the appropriate key size: 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
    key_encrip = key_encrip[:32].ljust(32, b'\0')  # Adjust the size to 32 bytes (256 bits)

    image_file = col1.file_uploader("Choose an Image", type=["png", "jpg", "jpeg"])
    # key = "kuncirahasiaanda"
    if message and key_encrip and image_file:
        image = Image.open(image_file)
        enkrip_message  = encrypt_text(key_encrip, message)
        encode_message(enkrip_message, image)

    st.markdown("---")
with tab2:
    col3, col4 = st.columns(2)
    col3.header("Decode")
    
    key_decrip = col3.text_input("Enter Key Decode")

    # Convert the key to bytes using UTF-8 encoding
    key_decrip = key_decrip.encode('utf-8')

    # Choose the appropriate key size: 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
    key_decrip = key_decrip[:32].ljust(32, b'\0')  # Adjust the size to 32 bytes (256 bits)

    decode_image_file = col3.file_uploader("Choose an Encoded Image", type=["png", "jpg", "jpeg"])
    if decode_image_file and key_decrip:
        decode_image = Image.open(decode_image_file)
        decode_message(decode_image)
    st.markdown("---")

