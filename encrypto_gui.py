import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from encryption import encrypt, decrypt, generate_aes_key  # assuming these functions exist in encryption.py

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Program")
        self.algorithms = ['caesar', 'simple_substitution', 'AES']
        self.setup_layout()

    def setup_layout(self):
        tk.Label(self.root, text="Select Algorithm:").grid(row=0, column=0, padx=5, pady=5)
        self.algorithm_combo = ttk.Combobox(self.root, values=self.algorithms)
        self.algorithm_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.algorithm_combo.current(0)

        tk.Label(self.root, text="Enter Password/Key:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.root)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        tk.Label(self.root, text="Input Text:").grid(row=2, column=0, padx=5, pady=5, sticky="nw")
        self.input_text = tk.Text(self.root, height=10)
        self.input_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        actions = [('Encrypt', self.perform_encryption), ('Decrypt', self.perform_decryption)]
        for i, (text, command) in enumerate(actions):
            tk.Button(self.root, text=text, command=command).grid(row=4, column=i, padx=5, pady=5)

    def perform_encryption(self):
        self.perform_action(action='encrypt')

    def perform_decryption(self):
        self.perform_action(action='decrypt')

    def perform_action(self, action):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            if not text:
                raise ValueError(f"Please enter some text to {action}.")

            algorithm = self.algorithm_combo.get()
            key = self.get_key_for_algorithm(algorithm)
            result_text = encrypt(text, algorithm, key) if action == 'encrypt' else decrypt(text, algorithm, key)

            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", result_text)
            messagebox.showinfo("Success", f"Text {action}ed successfully.")
        except Exception as e:
            messagebox.showerror(f"{action.capitalize()} Error", str(e))

    def get_key_for_algorithm(self, algorithm):
        if algorithm == 'simple_substitution':
            key = simpledialog.askstring("Key", "Enter 26 unique characters:", parent=self.root)
            if not key or len(set(key.lower())) != 26 or not key.isalpha():
                raise ValueError("Invalid key for simple substitution.")
        elif algorithm == 'AES':
            key = self.password_entry.get()
            if len(key) not in (16, 24, 32):  # AES key must be either 16, 24, or 32 bytes
                raise ValueError("Invalid key length for AES. Must be 16, 24, or 32 bytes.")
        else:
            key = self.password_entry.get()
        return key

if __name__ == "__main__":
    app = EncryptionApp(tk.Tk())
    app.root.mainloop()
