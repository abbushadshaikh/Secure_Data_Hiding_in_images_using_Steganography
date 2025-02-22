AICTE INTERNSHIP PROJECT
# Secure Data Hiding Using Steganography

##  Project Overview: 
This project allows users to **securely hide encrypted messages** inside images using **steganography**. It combines **cryptography and image processing** to ensure that sensitive data remains hidden and only retrievable by authorized users with the correct password.  

##  Key Features:   
✅ **Secure Image-Based Encryption** – Encrypts and embeds messages inside images.  
✅ **User-Friendly GUI** – Easy-to-use interface powered by **Tkinter**.  
✅ **Password Protection** – Only users with the correct password can decrypt the hidden message.  
✅ **"Show Location" Button** – Quickly view encrypted & decrypted file paths.  
✅ **Cross-Platform Support** – Works on **Windows, Linux (Kali, Ubuntu), and macOS as long as they have pyhton**.  


## 🛠️ Installation:

### **Install Required Dependencies**  
Run the following command to install all required libraries:  


" pip install opencv-python numpy cryptography "

Usage:

🔹 Encrypt a Message into an Image: 

1. Run the script: python secure_data_hiding_using_steganography.py
2. Select an image file (.png).
3. Enter your secret message and password.
4. Click "Encrypt Image" – The encoded image will be saved as encoded_image.png.


🔹 Decrypt a Message from an Image

1. Run the script and click "Decrypt Image".
2. Select the encrypted image and enter the correct password.
3. The decrypted message is saved in decrypted_message.txt.

Security Features: 

1. End-to-End Encryption: Messages are encrypted using Fernet (AES-128) before being hidden.
2. Steganography-Based Storage: Data is hidden in image pixels' Least Significant Bit (LSB).
3. Password Protection: Without the correct password, decryption is very hard.


📌 Future Scope:

🔹 Support for additional image formats (JPEG, BMP)

🔹 Stronger encryption algorithms (AES-256, RSA)

🔹 Mobile and web-based implementations

🔹 AI-driven steganalysis resistance improvements
