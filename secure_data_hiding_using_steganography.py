import cv2
import numpy as np
import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import subprocess
from cryptography.fernet import Fernet

def generate_key(password):
    return base64.urlsafe_b64encode(password.ljust(32).encode()[:32])

def encrypt_message(message, password):
    key = generate_key(password)
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, password):
    try:
        key = generate_key(password)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_message).decode()
    except:
        return "Incorrect password or corrupted data."

def encrypt_image(image_path, message, password):
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Could not open the image.")
        return

    encrypted_message = encrypt_message(message, password)
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
    binary_message += '1111111111111110'  # End of message indicator

    encoded_image = image.copy()
    height, width, _ = encoded_image.shape
    x, y = 0, 0

    for bit in binary_message:
        if x == width:
            x = 0
            y += 1
        if y >= height:
            messagebox.showerror("Error", "Image is too small to hold the message.")
            return
        pixel = encoded_image[y, x]
        encoded_image[y, x, 2] = np.uint8((pixel[2] & 0b11111110) | int(bit))  # FIXED LINE
        x += 1

    global encrypted_image_path
    encrypted_image_path = os.path.abspath("encoded_image.png")
    cv2.imwrite(encrypted_image_path, encoded_image, [cv2.IMWRITE_PNG_COMPRESSION, 0])
    messagebox.showinfo("Success", "Image encrypted successfully!")

    password_entry.delete(0, tk.END)
    message_entry.delete(0, tk.END)

def decrypt_image(image_path, password):
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Could not open the image.")
        return

    height, width, _ = image.shape
    binary_message = ''
    x, y = 0, 0

    while True:
        if x == width:
            x = 0
            y += 1
        if y >= height:
            break
        pixel = image[y, x]
        binary_message += str(pixel[2] & 1)
        x += 1
        if binary_message[-16:] == '1111111111111110':
            break

    binary_message = binary_message[:-16]
    encrypted_bytes = bytearray()
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        encrypted_bytes.append(int(byte, 2))

    encrypted_message = bytes(encrypted_bytes)
    decrypted_message = decrypt_message(encrypted_message, password)

    global decrypted_message_path
    decrypted_message_path = os.path.abspath("decrypted_message.txt")
    with open(decrypted_message_path, "w") as file:
        file.write(decrypted_message)

    messagebox.showinfo("Success", "Decrypted message saved successfully!")

    password_entry.delete(0, tk.END)

def select_image_file():
    image_path = filedialog.askopenfilename(filetypes=[("Image Files", ".png")])
    return image_path

def open_folder(path):
    try:
        if os.name == 'nt':
            os.startfile(path)  # Windows
        elif os.name == 'posix':
            subprocess.run(['xdg-open', path], check=True)  # Linux
        else:
            subprocess.run(['open', path], check=True)  # macOS
    except Exception as e:
        messagebox.showerror("Error", f"Could not open folder: {e}")

def show_file_locations():
    options = ["Encrypted Image", "Decrypted Message"]
    selected_option = messagebox.askquestion("Show Location", "Which file location do you want to see?\nYes for Encrypted Image, No for Decrypted Message.")

    if selected_option == "yes":
        messagebox.showinfo("Encrypted Image Location", f"Location: {encrypted_image_path}")
    else:
        messagebox.showinfo("Decrypted Message Location", f"Location: {decrypted_message_path}")

def toggle_password():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
    else:
        password_entry.config(show='*')

def encrypt_action():
    image_path = select_image_file()
    if not image_path:
        return
    message = message_entry.get()
    password = password_entry.get()
    encrypt_image(image_path, message, password)

def decrypt_action():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter the password first.")
        return

    messagebox.showinfo("Select Image", "Please select the encrypted image file for decryption.")
    image_path = select_image_file()
    if not image_path:
        return

    decrypt_image(image_path, password)

# GUI Setup
root = tk.Tk()
root.title("Secure Data Hiding Using Steganography")
root.geometry("400x400")

ttk.Label(root, text="Secret Message:").pack()
message_entry = ttk.Entry(root, width=40)
message_entry.pack()

ttk.Label(root, text="Password:").pack()
password_frame = ttk.Frame(root)
password_frame.pack()
password_entry = ttk.Entry(password_frame, width=30, show='*')
password_entry.pack(side=tk.LEFT)
toggle_button = ttk.Button(password_frame, text="Show", command=toggle_password)
toggle_button.pack(side=tk.RIGHT)

encrypt_button = ttk.Button(root, text="Encrypt Image", command=encrypt_action)
encrypt_button.pack(pady=10)

decrypt_button = ttk.Button(root, text="Decrypt Image", command=decrypt_action)
decrypt_button.pack(pady=10)

show_location_button = ttk.Button(root, text="Show Location", command=show_file_locations)
show_location_button.pack(pady=10)

open_enc_folder_button = ttk.Button(root, text="Open Encrypted Folder", command=lambda: open_folder(os.path.dirname(encrypted_image_path)))
open_enc_folder_button.pack(pady=10)

open_dec_folder_button = ttk.Button(root, text="Open Decryption Folder", command=lambda: open_folder(os.path.dirname(decrypted_message_path)))
open_dec_folder_button.pack(pady=10)

root.mainloop()
