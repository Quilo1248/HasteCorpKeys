#!/usr/bin/env python3
# tabs-only indentation
import base64
import json
import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import customtkinter as ctk
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
	Ed25519PrivateKey,
	Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# ------------------------------
# CONFIG - update this to your repo/raw path if different
# ------------------------------
# Raw URL should point to data/data.json inside your repo
# Example: "https://raw.githubusercontent.com/Quilo1248/HasteCorpKeys/main/data/data.json"
DATA_URL = "https://raw.githubusercontent.com/Quilo1248/HasteCorpKeys/refs/heads/main/data/data.json"

# Local fallback path (if users bundle data/data.json in the app distribution)
LOCAL_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "data.json"

# Globals for loaded data
public_keys = {}
revoked_employees = []

# ------------------------------
# Data fetching / loading
# ------------------------------
def load_local_data():
	"""Load data.json from local data/ folder if present."""
	try:
		if LOCAL_DATA_PATH.exists():
			with open(LOCAL_DATA_PATH, "r") as f:
				return json.load(f)
	except Exception:
		pass
	return {"public_keys": {}, "revoked": []}

def fetch_data():
	"""Try remote fetch first, fall back to local file if remote fails.
	Returns (success: bool, message: str)
	"""
	global public_keys, revoked_employees
	try:
		r = requests.get(DATA_URL, timeout=8)
		r.raise_for_status()
		data = r.json()
		if not isinstance(data, dict):
			raise ValueError("data.json not an object")
		public_keys = data.get("public_keys", {}) or {}
		revoked_employees = data.get("revoked", []) or []
		return True, "Loaded data from remote"
	except Exception as e:
		local = load_local_data()
		if local.get("public_keys") or local.get("revoked"):
			public_keys = local.get("public_keys", {}) or {}
			revoked_employees = local.get("revoked", []) or []
			return True, f"Remote fetch failed ({e}); loaded local data"
		return False, f"Failed to load data: {e}. No local fallback."

# ------------------------------
# Crypto helpers
# ------------------------------
def load_private_key(b64_key: str) -> Ed25519PrivateKey:
	return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64_key))

def load_public_key(b64_key: str) -> Ed25519PublicKey:
	return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64_key))

def sign_pass(private_key: Ed25519PrivateKey, username: str, session: int, emp_id: str) -> str:
	payload = {
		"username": username,
		"valid_until_session": session,
		"issued_by": emp_id,
	}
	json_bytes = json.dumps(payload).encode()
	signature = private_key.sign(json_bytes)
	return base64.b64encode(signature).decode()

def verify_pass_payload(payload: dict, sig_b64: str) -> (bool, str):
	try:
		issuer = payload.get("issued_by")
		if not issuer:
			return False, "Missing issuer"
		pub_b64 = public_keys.get(issuer)
		if not pub_b64:
			return False, "Issuer public key not found"
		pub_key = load_public_key(pub_b64)
		pub_key.verify(base64.b64decode(sig_b64), json.dumps(payload).encode())
		return True, "Signature valid"
	except Exception as e:
		return False, f"Signature invalid: {e}"

def parse_pass_text(pasted_text: str):
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
			try:
				payload["valid_until_session"] = int(line.split(":", 1)[1].strip())
			except Exception:
				return None, "Invalid session number"
		elif lower.startswith("issued by:"):
			payload["issued_by"] = line.split(":", 1)[1].strip()
		elif lower.startswith("key:"):
			sig_b64 = line.split(":", 1)[1].strip()
	if not payload or sig_b64 is None:
		return None, "Pass missing fields"
	return (payload, sig_b64), None

# ------------------------------
# GUI App
# ------------------------------
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class StorePassApp(ctk.CTk):
	def __init__(self):
		super().__init__()
		self.title("Minecraft StorePass")
		self.geometry("700x520")

		self.private_key = None
		self.emp_id = None
		self.logged_in = False

		self.initial_data_status = fetch_data()
		self._build_login_ui()

	def clear_window(self):
		for w in self.winfo_children():
			w.destroy()

	# ------------------------------
	# Login UI
	# ------------------------------
	def _build_login_ui(self):
		self.clear_window()

		container = ctk.CTkFrame(self)
		container.pack(expand=True, fill="both", padx=20, pady=20)

		ctk.CTkLabel(
			container,
			text="Employee Login",
			font=ctk.CTkFont(size=20, weight="bold"),
		).pack(pady=(6, 12))

		frm = ctk.CTkFrame(container)
		frm.pack(padx=8, pady=6, fill="x")

		ctk.CTkLabel(frm, text="Employee ID").grid(
			row=0, column=0, sticky="w", padx=6, pady=6
		)
		self.login_emp_id = ctk.CTkEntry(frm)
		self.login_emp_id.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

		ctk.CTkLabel(frm, text="Private Key (base64)").grid(
			row=1, column=0, sticky="w", padx=6, pady=6
		)
		self.login_priv = ctk.CTkEntry(frm, show="*")
		self.login_priv.grid(row=1, column=1, sticky="ew", padx=6, pady=6)

		frm.grid_columnconfigure(1, weight=1)

		btn_row = ctk.CTkFrame(container)
		btn_row.pack(pady=12)

		login_btn = ctk.CTkButton(
			btn_row, text="Login (syncs automatically)", width=200, command=self._handle_login
		)
		login_btn.grid(row=0, column=0, padx=8)

		skip_btn = ctk.CTkButton(
			btn_row,
			text="Skip verification",
			width=160,
			fg_color="#9aa9ff",
			hover_color="#7f95ff",
			command=self._handle_skip,
		)
		skip_btn.grid(row=0, column=1, padx=8)

		status_row = ctk.CTkFrame(container)
		status_row.pack(pady=6, fill="x")

		self.login_status = ctk.CTkLabel(
			status_row, text="Waiting for login...", anchor="w"
		)
		self.login_status.pack(side="left", padx=6)

		ok, msg = self.initial_data_status
		if ok:
			self.login_status.configure(text=f"Data loaded: {msg}")
		else:
			self.login_status.configure(text=f"Failed loading data: {msg}")

	def _handle_login(self):
		priv_b64 = self.login_priv.get().strip()
		emp_id = self.login_emp_id.get().strip()
		if not priv_b64 or not emp_id:
			messagebox.showerror("Login", "Both Employee ID and private key are required")
			return

		self.login_status.configure(text="🔄 Syncing with Git...")
		self.update_idletasks()

		ok, msg = fetch_data()
		if ok:
			self.login_status.configure(text=f"✅ Synced: {msg}")
		else:
			self.login_status.configure(text=f"⚠️ Sync failed: {msg}")

		ok, msg = self._validate_employee_login(priv_b64, emp_id)
		if ok:
			self.private_key = load_private_key(priv_b64)
			self.emp_id = emp_id
			self.logged_in = True
			messagebox.showinfo("Login", "✅ Login successful")
			self._build_main_ui()
		else:
			messagebox.showerror("Login failed", msg)

	def _handle_skip(self):
		# show syncing status
		self.login_status.configure(text="🔄 Syncing with Git (skip mode)...")
		self.update_idletasks()

		ok, msg = fetch_data()
		if ok:
			self.login_status.configure(text=f"✅ Synced: {msg}")
		else:
			self.login_status.configure(text=f"⚠️ Sync failed: {msg}")

		# skip validation, but still enter app
		self.logged_in = True
		self.emp_id = "SKIPPED"
		self.private_key = None
		messagebox.showwarning(
		    "Login Skipped",
		    "You skipped verification.\nSome features may not work.",
		)
		self._build_main_ui()


	def _validate_employee_login(self, priv_key_b64: str, emp_id: str) -> (bool, str):
		try:
			if emp_id not in public_keys:
				return False, "Employee ID not found in data.json"
			priv_bytes = base64.b64decode(priv_key_b64)
			private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
			public_key = private_key.public_key()
			pub_bytes = public_key.public_bytes(
				encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
			)
			pub_b64 = base64.b64encode(pub_bytes).decode("utf-8")
			if public_keys.get(emp_id) != pub_b64:
				return False, "Private key does not match public key in data.json"
			if emp_id in revoked_employees:
				return False, "Employee ID is revoked."
			return True, "Key validated"
		except Exception as e:
			return False, f"Invalid private key: {e}"

	# ------------------------------
	# Main UI
	# ------------------------------
	def _build_main_ui(self):
		self.clear_window()

		topbar = ctk.CTkFrame(self)
		topbar.pack(fill="x", padx=8, pady=8)

		account_text = (
			f"Logged in: {self.emp_id}"
			if self.logged_in
			else "Not logged in (verification only)"
		)
		self.account_label = ctk.CTkLabel(topbar, text=account_text, anchor="w")
		self.account_label.pack(side="left", padx=8)

		sync_btn = ctk.CTkButton(
			topbar, text="Sync from Git", width=140, command=self._sync_action
		)
		sync_btn.pack(side="right", padx=8)

		tabs = ctk.CTkTabview(self)
		tabs.pack(expand=True, fill="both", padx=12, pady=6)
		tabs.add("Create Pass")
		tabs.add("Verify Pass")

		# -------- Create Pass --------
		create_tab = tabs.tab("Create Pass")
		ctk.CTkLabel(
			create_tab,
			text="Create a Minecraft Book Pass",
			font=ctk.CTkFont(size=16, weight="bold"),
		).pack(pady=8)

		form = ctk.CTkFrame(create_tab)
		form.pack(padx=8, pady=6, fill="x")

		ctk.CTkLabel(form, text="Minecraft Username").grid(
			row=0, column=0, sticky="w", padx=6, pady=6
		)
		self.c_username = ctk.CTkEntry(form)
		self.c_username.grid(row=0, column=1, sticky="ew", padx=6, pady=6)

		ctk.CTkLabel(form, text="Valid Until Session (number)").grid(
			row=1, column=0, sticky="w", padx=6, pady=6
		)
		self.c_session = ctk.CTkEntry(form)
		self.c_session.grid(row=1, column=1, sticky="ew", padx=6, pady=6)

		form.grid_columnconfigure(1, weight=1)

		btn_row = ctk.CTkFrame(create_tab)
		btn_row.pack(pady=8)
		self.generate_btn = ctk.CTkButton(
			btn_row, text="Generate Pass", command=self._generate_pass, width=160
		)
		self.generate_btn.grid(row=0, column=0, padx=8)

		self.copy_btn = ctk.CTkButton(
			btn_row, text="Copy to clipboard", command=self._copy_pass_to_clipboard, width=160
		)
		self.copy_btn.grid(row=0, column=1, padx=8)

		self.pass_output = scrolledtext.ScrolledText(create_tab, height=6)
		self.pass_output.pack(padx=8, pady=8, fill="both", expand=True)

		if not self.logged_in or not self.private_key:
			self.generate_btn.configure(state="disabled")
			self.copy_btn.configure(state="disabled")
		elif self.emp_id in revoked_employees:
			self.generate_btn.configure(state="disabled", text="Employee Revoked")
			self.copy_btn.configure(state="disabled")
			messagebox.showwarning(
				"Account Status",
				f"Your employee ID ({self.emp_id}) has been revoked. "
				"Cannot create new passes."
			)

		# -------- Verify Pass --------
		verify_tab = tabs.tab("Verify Pass")
		ctk.CTkLabel(
			verify_tab,
			text="Verify a customer's pass",
			font=ctk.CTkFont(size=16, weight="bold"),
		).pack(pady=8)

		vs_frame = ctk.CTkFrame(verify_tab)
		vs_frame.pack(padx=8, pady=6, fill="x")

		ctk.CTkLabel(vs_frame, text="Current Session Number").grid(
			row=0, column=0, sticky="w", padx=6, pady=6
		)
		self.v_current_session = ctk.CTkEntry(vs_frame)
		self.v_current_session.grid(row=0, column=1, sticky="ew", padx=6, pady=6)
		vs_frame.grid_columnconfigure(1, weight=1)

		self.verify_input = scrolledtext.ScrolledText(verify_tab, height=8)
		self.verify_input.pack(padx=8, pady=8, fill="both", expand=True)

		verify_btn_row = ctk.CTkFrame(verify_tab)
		verify_btn_row.pack(pady=6)
		verify_btn = ctk.CTkButton(
			verify_btn_row, text="Verify Pass", command=self._verify_pass_gui, width=160
		)
		verify_btn.grid(row=0, column=0, padx=8)
		clear_btn = ctk.CTkButton(
			verify_btn_row,
			text="Clear",
			command=lambda: self.verify_input.delete("1.0", tk.END),
			width=100,
		)
		clear_btn.grid(row=0, column=1, padx=8)

		note = ctk.CTkLabel(
			verify_tab,
			text="Tip: Use 'Sync from Git' if keys seem missing or outdated.",
			anchor="w",
		)
		note.pack(padx=8, pady=(4, 12), fill="x")

	# ------------------------------
	# Actions
	# ------------------------------
	def _sync_action(self):
		ok, msg = fetch_data()
		if ok:
			messagebox.showinfo("Sync", f"✅ {msg}")
		else:
			messagebox.showerror("Sync", f"❌ {msg}")

	def _generate_pass(self):
		if not self.logged_in or not self.private_key or not self.emp_id:
			messagebox.showerror("Generate", "You must be logged in to generate passes")
			return
		if self.emp_id in revoked_employees:
			messagebox.showerror(
				"Generate",
				f"Your employee ID ({self.emp_id}) has been revoked. "
				"Cannot create new passes. Please re-sync and check your status."
			)
			if hasattr(self, 'generate_btn'):
				self.generate_btn.configure(state="disabled", text="Employee Revoked")
				self.copy_btn.configure(state="disabled")
			return

		username = self.c_username.get().strip()
		session = self.c_session.get().strip()
		if not username or not session.isdigit():
			messagebox.showerror("Generate", "Invalid username or session")
			return
		sig = sign_pass(self.private_key, username, int(session), self.emp_id)
		pass_text = (
			f"username: {username}\nvalid until session: {session}\n"
			f"issued by: {self.emp_id}\nkey: {sig}"
		)
		self.pass_output.delete("1.0", tk.END)
		self.pass_output.insert(tk.END, pass_text)

	def _copy_pass_to_clipboard(self):
		pass_text = self.pass_output.get("1.0", tk.END).strip()
		if not pass_text:
			messagebox.showerror("Copy", "No pass generated")
			return
		self.clipboard_clear()
		self.clipboard_append(pass_text)
		messagebox.showinfo("Copy", "✅ Pass copied to clipboard")

	def _verify_pass_gui(self):
		text = self.verify_input.get("1.0", tk.END).strip()
		if not text:
			messagebox.showerror("Verify", "No pass text provided")
			return
		result, err = parse_pass_text(text)
		if err:
			messagebox.showerror("Verify", err)
			return
		payload, sig_b64 = result
		ok, msg = verify_pass_payload(payload, sig_b64)
		if not ok:
			messagebox.showerror("Verify", msg)
			return
		current_session = self.v_current_session.get().strip()
		if not current_session.isdigit():
			messagebox.showerror("Verify", "Invalid current session number")
			return
		current_session = int(current_session)
		valid_until = payload.get("valid_until_session")
		if valid_until is None:
			messagebox.showerror("Verify", "Pass missing session validity")
			return
		if current_session > valid_until:
			messagebox.showerror("Verify", "Pass expired for this session")
			return
		if payload.get("issued_by") in revoked_employees:
			messagebox.showerror("Verify", "Pass issuer is revoked")
			return
		messagebox.showinfo(
			"Verify",
			f"✅ Valid pass!\n\n"
			f"Username: {payload.get('username')}\n"
			f"Issued by: {payload.get('issued_by')}\n"
			f"Valid until session: {valid_until}\n"
		)

# ------------------------------
if __name__ == "__main__":
	app = StorePassApp()
	app.mainloop()

