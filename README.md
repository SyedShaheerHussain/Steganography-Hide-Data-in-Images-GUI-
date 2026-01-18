# 🔐 Image Steganography Tool (LSB + AES)

This project hides secret text messages inside images using Least Significant Bit (LSB) steganography combined with AES-256 password-based encryption.

# Description

This project is a Python-based GUI application that enables image steganography, allowing users to hide and extract secret messages inside images.

Messages can be protected with a password using AES-256 encryption.

The hidden data is embedded into images using the LSB (Least Significant Bit) technique.

The GUI is modern and responsive, divided into two main tabs:

Hide Message Tab – Select an image, type a secret message, enter a password, and hide the message inside the image.

Extract Message Tab – Upload an encoded image, enter the correct password, and extract the hidden message.

This tool is fully functional and suitable for both beginners and professionals who want to learn or use secure communication and data hiding techniques.

## 📌 Overview
This project hides secret text messages inside images using
Least Significant Bit (LSB) steganography combined with AES-256
password-based encryption.

The image looks visually unchanged while securely carrying
encrypted data.

## 🚀 Features
- LSB Image Steganography
- AES-256 Password Encryption
- Hide messages in any RGB image (PNG, JPG, JPEG)
- Extract hidden messages from images
- Password protected messages using AES encryption
- Image preview before hiding/extracting
- Progress bar for encoding process
- Multi-threaded operations for responsive UI
- Works on Windows/Linux/Mac
- Dark Mode GUI
- Image Preview
- Encode & Decode Messages
- No Quality Loss
- Python Tkinter GUI

## 🛠 How It Works

Hide Message Tab

Select an image from your device.

Type your secret message in the text box.

Enter a password to encrypt the message.

Click "Hide Message".

Save the encoded image with a new name.

Extract Message Tab

Select the encoded image you just saved.

Enter the same password used for hiding.

Click "Extract Message".

The hidden message will appear in the text box.

Technical Details:

LSB steganography hides message bits in the least significant bit of each RGB channel.

AES encryption (via Python cryptography library) encrypts the message before hiding it.

Only correct password can decrypt and reveal the message.

## 🛠 Technologies Used
- Python
- Pillow (Image Processing)
- Cryptography (AES Encryption)
- Tkinter (GUI)

## 🖥 Installation

Requirements:

Python 3.10+

Libraries: Pillow, cryptography

Step 1: Install Python packages

```pip install Pillow cryptography```

Step 2: Clone or download this repository

```
git clone <repo-url>
cd <repo-folder>
```


Step 3: Run the application

```python mainapp.py```

## 📝 Usage Steps

Hide a Message:

Open the app.

Go to Hide Message Tab.

Click Select Image and choose an image.

Type your secret message in the text box.

Enter a password.

Click Hide Message.

Save the encoded image anywhere with a custom name.

Extract a Message:

Go to Extract Message Tab.

Upload the encoded image.

Enter the same password used during hiding.

Click Extract Message.

The decrypted message will appear in the text box.

## 🖇 Functions Overview

| Function                              | Description                                               |
| ------------------------------------- | --------------------------------------------------------- |
| `generate_key(password)`              | Creates an AES key from password.                         |
| `encrypt_text(text, password)`        | Encrypts a message using AES.                             |
| `decrypt_text(text, password)`        | Decrypts message using AES.                               |
| `select_encode_image()`               | Opens file dialog to choose image for encoding.           |
| `select_decode_image()`               | Opens file dialog to choose image for decoding.           |
| `encode_message()`                    | Hides encrypted message in selected image.                |
| `decode_message()`                    | Extracts and decrypts message from image.                 |
| `resize_for_preview(image)`           | Resizes image for preview box while keeping aspect ratio. |
| `show_image_on_canvas(image, canvas)` | Displays image on GUI canvas.                             |

## 💡 Notes

Make sure the message size fits the image. Large messages may exceed capacity.

Use strong passwords for secure encryption.

Supports RGB images only.

Always save the encoded image with a different filename to avoid overwriting the original.

## 🎯 Conclusion

This project provides a secure and user-friendly tool for hiding secret messages in images. With AES encryption + LSB steganography, it ensures both privacy and data concealment.

Perfect for:

Students learning steganography

Secure message sharing

Fun encryption projects
