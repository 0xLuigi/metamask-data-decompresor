import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import re
import sys
import base64
from base64 import b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey
import os

class VaultDecryptor:
    """Core vault decryption functionality."""
    
    @staticmethod
    def decrypt_vault(password, vault):
        """
        Decrypt MetaMask vault data.
        Supports various vault data formats.
        """
        if isinstance(vault, dict) and 'data' in vault and isinstance(vault['data'], dict) and 'mnemonic' in vault['data']:
            return [vault]

        try:
            # Check if vault contains required keys
            required_keys = ["data", "iv", "salt"]
            for key in required_keys:
                if key not in vault:
                    raise Exception(f"Missing key '{key}' in vault data.")

            # Decode base64 strings
            encrypted_data = b64decode(vault["data"])
            iv = b64decode(vault["iv"])
            salt = b64decode(vault["salt"])

            # Get iterations from keyMetadata if exists
            iterations = 10000  # default value for older versions
            if "keyMetadata" in vault and "params" in vault["keyMetadata"] and "iterations" in vault["keyMetadata"]["params"]:
                iterations = vault["keyMetadata"]["params"]["iterations"]

            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 key
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))

            # Decrypt data using AES-GCM
            aesgcm = AESGCM(key)
            decrypted_payload = aesgcm.decrypt(iv, encrypted_data, None)

            # Decode JSON
            decrypted_json = json.loads(decrypted_payload.decode('utf-8'))
            
            # Process mnemonic if exists
            if isinstance(decrypted_json, list):
                for keyring in decrypted_json:
                    if 'data' in keyring and 'mnemonic' in keyring['data']:
                        mnemonic = keyring['data']['mnemonic']
                        if isinstance(mnemonic, list):
                            # If mnemonic is byte array, convert to string
                            keyring['data']['mnemonic'] = bytes(mnemonic).decode('utf-8')
                        elif not isinstance(mnemonic, str):
                            # If not string, try to convert
                            keyring['data']['mnemonic'] = str(mnemonic)

            return decrypted_json

        except InvalidKey:
            raise Exception("Incorrect password or corrupted vault data.")
        except json.JSONDecodeError:
            raise Exception("Error decoding JSON data.")
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")

    @staticmethod
    def extract_vault_from_text(text):
        """
        Extract vault data from text input.
        Supports JSON format and raw text.
        """
        text = text.strip()
        
        # Try direct JSON parsing
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # If not JSON, try to extract as from file
        return VaultDecryptor.extract_vault_from_file(text)

    @staticmethod
    def extract_vault_from_file(data):
        """
        Extract vault data from various file formats.
        """
        # Attempt 1: raw json
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            pass

        # Attempt 2: pre-v3 cleartext
        matches = re.search(r'{"wallet-seed":"([^"]*)"}', data)
        if matches:
            mnemonic = matches.group(1).replace("\\n*", "")
            vault_matches = re.search(r'"wallet":("{[ -~]*\\"version\\":2}")', data)
            vault = json.loads(json.loads(vault_matches.group(1))) if vault_matches else {}
            return {
                "data": {
                    "mnemonic": mnemonic,
                    **vault
                }
            }

        # Attempt 3: chromium 000003.log file on linux
        matches = re.search(r'"KeyringController":{"vault":"({[^{}]*})"}', data)
        if matches:
            vault_body = matches.group(1)
            return json.loads(json.loads(vault_body))

        # Attempt 4 & 5: chromium logs with base64 encoded data
        matches = re.search(r'"KeyringController":(\{.*?"vault":".*?=\\"\})', data)
        if matches:
            keyring_controller_state_fragment = matches.group(1)
            data_match = re.search(r'\\"data\\":\\"([A-Za-z0-9+\/]*=*)\\"', keyring_controller_state_fragment)
            iv_match = re.search(r',\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)\\"', keyring_controller_state_fragment)
            salt_match = re.search(r',\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\"', keyring_controller_state_fragment)
            key_meta_match = re.search(r',\\"keyMetadata\\":(.*}})', keyring_controller_state_fragment)

            if data_match and iv_match and salt_match:
                vault_data = data_match.group(1)
                iv = iv_match.group(1)
                salt = salt_match.group(1)
                key_metadata = None
                if key_meta_match:
                    try:
                        key_metadata = json.loads(key_meta_match.group(1).replace("\\", ""))
                    except json.JSONDecodeError:
                        pass

                result = {
                    "data": vault_data,
                    "iv": iv,
                    "salt": salt
                }
                if key_metadata:
                    result["keyMetadata"] = key_metadata
                
                return result

        return None

    @staticmethod
    def is_vault_valid(vault):
        """
        Check if vault data is in valid format.
        """
        if not isinstance(vault, dict):
            return False
        
        # Check basic keys
        required_keys = ["data", "iv", "salt"]
        for key in required_keys:
            if key not in vault or not isinstance(vault[key], str):
                return False
        
        return True

class VaultDecryptorGUI:
    """GUI for the MetaMask Vault Decryptor."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("MetaMask Vault Decryptor (Python version)")
        self.root.geometry("650x600")
        self.root.configure(bg="#f0f0f0")
        
        # Nastavenie ikony okna
        try:
            icon_path = os.path.join(os.path.dirname(__file__), 'images', 'icon.ico')
            self.root.iconbitmap(icon_path)
        except tk.TclError as e:
            print(f"Warning: Could not load icon file 'images/icon.ico': {e}")

        # Variables
        self.vault_data = None
        
        self.create_widgets()
    
    def paste_vault_data(self):
        try:
            clipboard_content = self.root.clipboard_get()
            self.vault_text.delete(1.0, tk.END)
            self.vault_text.insert(tk.END, clipboard_content)
        except tk.TclError:
            messagebox.showwarning("Paste Error", "No content in clipboard or cannot access clipboard.")
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Vault data input section
        vault_frame = ttk.LabelFrame(main_frame, text="1. Vault Data", padding="10")
        vault_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        vault_frame.columnconfigure(0, weight=1)
        vault_frame.rowconfigure(1, weight=1)
        
        ttk.Label(vault_frame, text="Paste your vault data (JSON format):").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.vault_text = scrolledtext.ScrolledText(vault_frame, wrap=tk.WORD, height=8)
        self.vault_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Kontextové menu pre pole Vault Data
        self.vault_context_menu = tk.Menu(self.root, tearoff=0)
        self.vault_context_menu.add_command(label="Paste", command=self.paste_vault_data)
        self.vault_text.bind("<Button-3>", lambda event: self.vault_context_menu.tk_popup(event.x_root, event.y_root))
        
        # Load button
        self.load_button = tk.Button(vault_frame, text="Load Vault Data", command=self.load_vault_data,
                                    bg="#4CAF50", fg="white", activebackground="#2E7D32", activeforeground="white")
        self.load_button.grid(row=2, column=0, pady=(0, 5))
        
        # Password section
        password_frame = ttk.LabelFrame(main_frame, text="2. Password", padding="10")
        password_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        password_frame.columnconfigure(1, weight=1)
        
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = ttk.Checkbutton(password_frame, text="Show password", 
                                                  variable=self.show_password_var, 
                                                  command=self.toggle_password_visibility)
        self.show_password_check.grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        self.decrypt_button = tk.Button(password_frame, text="Decrypt", command=self.decrypt_vault,
                                       bg="#F57C00", fg="white", activebackground="#EF6C00", activeforeground="white")
        self.decrypt_button.grid(row=0, column=2)
        
        # Results section
        result_frame = ttk.LabelFrame(main_frame, text="3. Results", padding="10")
        result_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Results text widget
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=15)
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, pady=(10, 0))
        
        self.save_button = tk.Button(button_frame, text="Save Results", 
                                    command=self.save_results, state="disabled",
                                    bg="#4CAF50", fg="white", activebackground="#2E7D32", activeforeground="white")
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_all,
                                     bg="#F44336", fg="white", activebackground="#D32F2F", activeforeground="white")
        self.clear_button.pack(side=tk.LEFT)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure button style
        style = ttk.Style()
        style.configure('Custom.TButton', background='#4CAF50', foreground='white')
        style.map('Custom.TButton',
                  background=[('active', '#2E7D32')],
                  foreground=[('active', 'white')])
        
        # Bind Enter key for password
        self.password_entry.bind('<Return>', lambda event: self.decrypt_vault())
        
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            
    def load_vault_data(self):
        text_content = self.vault_text.get(1.0, tk.END).strip()
        
        if not text_content:
            messagebox.showwarning("Warning", "Please enter vault data in the text area.")
            return
            
        try:
            # Try to extract vault data from text
            self.vault_data = VaultDecryptor.extract_vault_from_text(text_content)
            
            if self.vault_data:
                if VaultDecryptor.is_vault_valid(self.vault_data):
                    self.status_var.set("Vault data loaded successfully")
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, "✅ Vault data loaded successfully.\n")
                    self.result_text.insert(tk.END, f"Type: {type(self.vault_data)}\n")
                    if isinstance(self.vault_data, dict):
                        self.result_text.insert(tk.END, f"Keys: {list(self.vault_data.keys())}\n")
                        if "keyMetadata" in self.vault_data and "params" in self.vault_data["keyMetadata"]:
                            iterations = self.vault_data["keyMetadata"]["params"].get("iterations", "unknown")
                            self.result_text.insert(tk.END, f"Iterations: {iterations}\n")
                else:
                    self.status_var.set("Vault data loaded but not valid")
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, "⚠️ Vault data loaded but not in valid format.\n")
            else:
                self.status_var.set("Could not extract vault data")
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "❌ Could not extract vault data from text.\n")
                self.result_text.insert(tk.END, "Please check the data format.\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error loading vault data: {str(e)}")
            self.status_var.set("Error loading vault data")
            
    def decrypt_vault(self):
        if not self.vault_data:
            messagebox.showwarning("Warning", "Please load vault data first.")
            return
            
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
            
        try:
            self.status_var.set("Decrypting...")
            self.root.update()
            
            decrypted_data = VaultDecryptor.decrypt_vault(password, self.vault_data)
            
            if decrypted_data:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "=== DECRYPTED VAULT DATA ===\n\n")
                
                if isinstance(decrypted_data, list):
                    for i, keyring in enumerate(decrypted_data):
                        self.result_text.insert(tk.END, f"Keyring {i + 1}:\n")
                        self.result_text.insert(tk.END, json.dumps(keyring, indent=2, ensure_ascii=False))
                        self.result_text.insert(tk.END, "\n\n")
                        
                        # Highlight mnemonic if exists
                        if 'data' in keyring and 'mnemonic' in keyring['data']:
                            self.result_text.insert(tk.END, f"🔑 MNEMONIC from keyring {i + 1}:\n")
                            self.result_text.insert(tk.END, f"{keyring['data']['mnemonic']}\n\n")
                else:
                    self.result_text.insert(tk.END, json.dumps(decrypted_data, indent=2, ensure_ascii=False))
                
                self.save_button.config(state="normal")
                self.status_var.set("Decryption successful")
            else:
                messagebox.showerror("Error", "Decryption failed. Please check your password.")
                self.status_var.set("Decryption failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {str(e)}")
            self.status_var.set("Decryption error")
            
    def save_results(self):
        if not self.result_text.get(1.0, tk.END).strip():
            messagebox.showwarning("Warning", "No results to save.")
            return
            
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(self.result_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Results saved successfully.")
                self.status_var.set("Results saved")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving file: {str(e)}")
                
    def clear_all(self):
        self.result_text.delete(1.0, tk.END)
        self.password_var.set("")
        self.vault_text.delete(1.0, tk.END)
        self.vault_data = None
        self.save_button.config(state="disabled")
        self.status_var.set("Ready")

def main():
    """Main function to run the application."""
    root = tk.Tk()
    app = VaultDecryptorGUI(root)
    
    # Check for command-line argument
    if len(sys.argv) > 1:
        try:
            vault_data = base64.b64decode(sys.argv[1]).decode('utf-8')
            app.vault_text.delete(1.0, tk.END)
            app.vault_text.insert(tk.END, vault_data)
            app.load_vault_data()
        except Exception as e:
            messagebox.showerror("Error", f"Error loading vault data from argument: {str(e)}")
    
    # Center the window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()