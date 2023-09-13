import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class EncryptDecryptApp:
    def __init__(self, master):
        self.master = master
        master.title("DAS Secure Message Platform")

        # Create the secret key input box
        self.secret_key_label = tk.Label(master, text="Enter Shared Encryption key:")
        self.secret_key_label.pack()

        self.secret_key = tk.Entry(master, show="*")
        self.secret_key.pack()

        # Create the message input box
        self.message_label = tk.Label(master, text="Enter message:")
        self.message_label.pack()

        self.message = tk.Text(master, height=20, width=100)
        self.message.pack()

        # Create the encrypt and decrypt buttons
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

    def encrypt_message(self):
        try:
            # Generate a random salt
            salt = get_random_bytes(16)
            key = PBKDF2(self.secret_key.get().encode(), salt, dkLen=32)

            # Use AES-256 in CBC mode
            cipher = AES.new(key, AES.MODE_CBC)

            # Pad the message so that its length is a multiple of 16
            padded_message = pad(self.message.get("1.0", tk.END).encode("utf-8"), AES.block_size)

            # Encrypt the padded message
            encrypted_message = cipher.encrypt(padded_message)

            # Combine the IV and the encrypted message
            iv = cipher.iv
            message = salt + iv + encrypted_message

            # Save the encrypted message to a file
            file_path = filedialog.asksaveasfilename(defaultextension=".enc")
            with open(file_path, "wb") as f:
                f.write(message)

            # Display a success message
            messagebox.showinfo("Success", "Message encrypted successfully!")

        except ValueError:
            messagebox.showerror("Error", "The secret key must be 16, 24, or 32 bytes long")

    def decrypt_message(self):
        try:
            # Load the encrypted message from a file
            file_path = filedialog.askopenfilename()
            with open(file_path, "rb") as f:
                message = f.read()

            # Extract the salt, IV, and encrypted message
            salt = message[:16]
            iv = message[16:16+AES.block_size]
            encrypted_message = message[16+AES.block_size:]

            # Derive the key using the salt
            key = PBKDF2(self.secret_key.get().encode(), salt, dkLen=32)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_message = cipher.decrypt(encrypted_message)

            # Remove the padding from the decrypted message
            message = unpad(padded_message, AES.block_size)

            # Display the decrypted message
            self.message.delete("1.0", tk.END)
            self.message.insert("1.0", message.decode("utf-8"))

            # Display a success message
            messagebox.showinfo("Success", "Message decrypted successfully!")

        except ValueError:
            messagebox.showerror("Error", "The secret key must be 16, 24, or 32 bytes long")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt the message: {str(e)}")

root = tk.Tk()
app = EncryptDecryptApp(root)
root.mainloop()
