#!/usr/bin/env python3
# tabs-only indentation
import base64
import json
import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import customtkinter as ctk
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# ------------------------------
# Git Repo Config
# ------------------------------
GIT_RAW_URL_BASE = "https://raw.githubusercontent.com/Quilo1248/HasteCorpKeys/main/"
PUBLIC_KEYS_FILE = "public_keys.json"
REVOKED_FILE = "revoked.json"

# ------------------------------
# Helpers
# ------------------------------
def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def sync_json_from_git(filename: str):
    url = f"{GIT_RAW_URL_BASE}{filename}"
    try:
        r = requests.get(url)
        r.raise_for_status()
        with open(filename, "w") as f:
            f.write(r.text)
        print(f"{filename} updated from Git")
        return True
    except Exception as e:
        print(f"Failed to fetch {filename}: {e}")
        return False

# Load JSONs
public_keys = load_json(PUBLIC_KEYS_FILE)
revoked_employees = load_json(REVOKED_FILE).get("revoked", [])

# ------------------------------
# Crypto Helpers
# ------------------------------
def load_private_key(b64_key: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64_key))

def load_public_key(b64_key: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64_key))

def sign_pass(private_key: Ed25519PrivateKey, username: str, session: int, emp_id: str) -> str:
    payload = {"username": username, "valid_until_session": session, "issued_by": emp_id}
    json_bytes = json.dumps(payload).encode()
    signature = private_key.sign(json_bytes)
    return base64.b64encode(signature).decode()

def verify_pass(pasted_text: str, current_session: int) -> (bool, str):
    try:
        payload = {}
        sig_b64 = None
        for line in pasted_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            if lower.startswith("username:"):
                payload["username"] = line.split(":", 1)[1].strip()
            elif lower.startswith("valid until session:"):
                payload["valid_until_session"] = int(line.split(":", 1)[1].strip())
            elif lower.startswith("issued by:"):
                payload["issued_by"] = line.split(":", 1)[1].strip()
            elif lower.startswith("key:"):
                sig_b64 = line.split(":", 1)[1].strip()
        if not payload or sig_b64 is None:
            return False, "Pass is missing fields"

        issuer = payload["issued_by"]
        if issuer in revoked_employees:
            return False, "Issuer is revoked"
        if payload["valid_until_session"] < current_session:
            return False, "Pass has expired"
        pub_key_b64 = public_keys.get(issuer)
        if not pub_key_b64:
            return False, "Issuer public key not found"
        pub_key = load_public_key(pub_key_b64)
        pub_key.verify(base64.b64decode(sig_b64), json.dumps(payload).encode())
        return True, "Pass is valid"
    except Exception as e:
        return False, f"Verification failed: {e}"

def validate_employee_login(priv_key_b64: str, emp_id: str) -> (bool, str):
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_key_b64))
    except Exception as e:
        return False, f"Invalid private key: {e}"
    public_key = private_key.public_key()
    pub_b64 = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    if emp_id not in public_keys:
        return False, "Employee ID not found in public keys"
    if public_keys[emp_id] != pub_b64:
        return False, "Private key does not match public key in directory"
    return True, "Employee key verified"

# ------------------------------
# GUI
# ------------------------------
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class StorePassApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Minecraft Store Pass System")
        self.geometry("600x520")

        # Tabs
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(expand=True, fill="both")
        self.tab_view.add("Settings")
        self.tab_view.add("Create Pass")
        self.tab_view.add("Verify Pass")

        # Settings tab
        self.private_key_input = ctk.CTkEntry(self.tab_view.tab("Settings"), placeholder_text="Paste your private key here")
        self.private_key_input.pack(pady=10, padx=10, fill="x")
        self.emp_id_input = ctk.CTkEntry(self.tab_view.tab("Settings"), placeholder_text="Your Employee ID")
        self.emp_id_input.pack(pady=10, padx=10, fill="x")
        self.save_button = ctk.CTkButton(self.tab_view.tab("Settings"), text="Save", command=self.save_settings)
        self.save_button.pack(pady=10)
        self.sync_button = ctk.CTkButton(self.tab_view.tab("Settings"), text="Sync Keys & Revoked from Git", command=self.sync_from_git)
        self.sync_button.pack(pady=10)

        # Create Pass tab
        self.username_entry = ctk.CTkEntry(self.tab_view.tab("Create Pass"), placeholder_text="Minecraft Username")
        self.username_entry.pack(pady=10, padx=10, fill="x")
        self.session_entry = ctk.CTkEntry(self.tab_view.tab("Create Pass"), placeholder_text="Valid Until Session (number)")
        self.session_entry.pack(pady=10, padx=10, fill="x")
        self.generate_button = ctk.CTkButton(self.tab_view.tab("Create Pass"), text="Generate Pass", command=self.generate_pass)
        self.generate_button.pack(pady=10)
        self.pass_output = scrolledtext.ScrolledText(self.tab_view.tab("Create Pass"), height=6)
        self.pass_output.pack(pady=10, padx=10, fill="both", expand=True)

        # Verify Pass tab
        self.current_session_entry = ctk.CTkEntry(self.tab_view.tab("Verify Pass"), placeholder_text="Current Session Number")
        self.current_session_entry.pack(pady=10, padx=10, fill="x")
        self.verify_input = scrolledtext.ScrolledText(self.tab_view.tab("Verify Pass"), height=6)
        self.verify_input.pack(pady=10, padx=10, fill="both", expand=True)
        self.verify_button = ctk.CTkButton(self.tab_view.tab("Verify Pass"), text="Verify Pass", command=self.verify_pass_gui)
        self.verify_button.pack(pady=10)

        self.private_key = None
        self.emp_id = None

    # ------------------------------
    # Actions
    # ------------------------------
    def save_settings(self):
        priv_key_b64 = self.private_key_input.get().strip()
        emp_id = self.emp_id_input.get().strip()
        if not priv_key_b64 or not emp_id:
            messagebox.showerror("Error", "Both fields are required")
            return

        valid, msg = validate_employee_login(priv_key_b64, emp_id)
        if valid:
            self.private_key = load_private_key(priv_key_b64)
            self.emp_id = emp_id
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Invalid Key", msg)

    def generate_pass(self):
        if not self.private_key or not self.emp_id:
            messagebox.showerror("Error", "Load your private key first")
            return
        username = self.username_entry.get().strip()
        session = self.session_entry.get().strip()
        if not username or not session.isdigit():
            messagebox.showerror("Error", "Invalid username or session")
            return
        signature = sign_pass(self.private_key, username, int(session), self.emp_id)
        pass_text = f"username: {username}\nvalid until session: {session}\nissued by: {self.emp_id}\nkey: {signature}"
        self.pass_output.delete("1.0", tk.END)
        self.pass_output.insert(tk.END, pass_text)

    def verify_pass_gui(self):
        pasted_text = self.verify_input.get("1.0", tk.END).strip()
        if not pasted_text:
            messagebox.showerror("Error", "Paste a pass to verify")
            return
        session = self.current_session_entry.get().strip()
        if not session.isdigit():
            messagebox.showerror("Error", "Invalid current session")
            return
        valid, reason = verify_pass(pasted_text, int(session))
        if valid:
            messagebox.showinfo("Result", f"✅ {reason}")
        else:
            messagebox.showerror("Result", f"❌ {reason}")

    def sync_from_git(self):
        ok1 = sync_json_from_git(PUBLIC_KEYS_FILE)
        ok2 = sync_json_from_git(REVOKED_FILE)
        if ok1 and ok2:
            global public_keys, revoked_employees
            public_keys = load_json(PUBLIC_KEYS_FILE)
            revoked_employees = load_json(REVOKED_FILE).get("revoked", [])
            messagebox.showinfo("Sync", "✅ Keys and revocation list updated from Git")
        else:
            messagebox.showerror("Sync", "❌ Failed to sync from Git")

if __name__ == "__main__":
    app = StorePassApp()
    app.mainloop()

