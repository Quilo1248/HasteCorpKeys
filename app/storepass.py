#!/usr/bin/env python3
# tabs-only indentation
import os
import sys
import json
import base64
import requests
import customtkinter as ctk
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

DATA_URL = "https://raw.githubusercontent.com/YourUser/YourRepo/main/data/data.json"

def fetch_data():
	try:
		resp = requests.get(DATA_URL, timeout=10)
		resp.raise_for_status()
		return resp.json()
	except Exception as e:
		print(f"Failed to fetch data.json: {e}")
		return {"public_keys": {}, "revoked": []}

def verify_employee(emp_id, private_key_b64, data):
	try:
		if emp_id not in data["public_keys"]:
			return False, "Employee ID not found"
		if emp_id in data["revoked"]:
			return False, "Employee revoked"

		priv_bytes = base64.b64decode(private_key_b64)
		private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
		public_key = private_key.public_key()

		pub_bytes = public_key.public_bytes(
			encoding=serialization.Encoding.Raw,
			format=serialization.PublicFormat.Raw
		)
		expected_pub_b64 = data["public_keys"][emp_id]

		if base64.b64encode(pub_bytes).decode("utf-8") != expected_pub_b64:
			return False, "Key mismatch"

		return True, "Valid employee"
	except Exception as e:
		return False, str(e)

class StorePassApp(ctk.CTk):
	def __init__(self):
		super().__init__()
		self.title("Minecraft Store Pass")
		self.geometry("400x250")

		ctk.CTkLabel(self, text="Employee Login", font=("Arial", 18)).pack(pady=10)

		self.id_entry = ctk.CTkEntry(self, placeholder_text="Employee ID")
		self.id_entry.pack(pady=5)

		self.key_entry = ctk.CTkEntry(self, placeholder_text="Private Key (base64)", show="*")
		self.key_entry.pack(pady=5)

		self.result_label = ctk.CTkLabel(self, text="")
		self.result_label.pack(pady=10)

		ctk.CTkButton(self, text="Login", command=self.login).pack(pady=10)

	def login(self):
		emp_id = self.id_entry.get().strip()
		private_key = self.key_entry.get().strip()
		data = fetch_data()
		ok, msg = verify_employee(emp_id, private_key, data)
		if ok:
			self.result_label.configure(text="✅ Access Granted", text_color="green")
		else:
			self.result_label.configure(text=f"❌ {msg}", text_color="red")

if __name__ == "__main__":
	app = StorePassApp()
	app.mainloop()

