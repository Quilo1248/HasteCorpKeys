#!/usr/bin/env python3
# tabs-only indentation
import json
import base64
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ------------------------------
# Paths
# ------------------------------
PUBLIC_KEYS_FILE = Path("public_keys.json")
REVOKED_FILE = Path("revoked.json")

# Ensure files exist
if not PUBLIC_KEYS_FILE.exists():
	PUBLIC_KEYS_FILE.write_text(json.dumps({}))
if not REVOKED_FILE.exists():
	REVOKED_FILE.write_text(json.dumps({"revoked": []}))

# ------------------------------
# JSON helpers
# ------------------------------
def load_json(file_path: Path):
	with open(file_path, "r") as f:
		return json.load(f)

def save_json(file_path: Path, data):
	with open(file_path, "w") as f:
		json.dump(data, f, indent=2)

# ------------------------------
# Key generation
# ------------------------------
def generate_keypair():
	private_key = Ed25519PrivateKey.generate()
	public_key = private_key.public_key()
	priv_b64 = base64.b64encode(private_key.private_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PrivateFormat.Raw,
		encryption_algorithm=serialization.NoEncryption()
	)).decode()
	pub_b64 = base64.b64encode(public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw
	)).decode()
	return priv_b64, pub_b64

# ------------------------------
# Git push helper
# ------------------------------
def push_updates_to_git():
	subprocess.run(["git", "add", "public_keys.json", "revoked.json"], check=True)
	subprocess.run(["git", "commit", "-m", "Update public keys / revoked list"], check=True)
	subprocess.run(["git", "push"], check=True)
	print("✅ Updates pushed to Git repository")

# ------------------------------
# Employee management
# ------------------------------
def add_employee(emp_id: str):
	public_keys = load_json(PUBLIC_KEYS_FILE)
	if emp_id in public_keys:
		print(f"Employee ID {emp_id} already exists!")
		return
	priv_b64, pub_b64 = generate_keypair()
	public_keys[emp_id] = pub_b64
	save_json(PUBLIC_KEYS_FILE, public_keys)
	print(f"✅ Employee {emp_id} added!\nSend PRIVATE key to employee:\n{priv_b64}")
	push_updates_to_git()

def revoke_employee(emp_id: str):
	revoked = load_json(REVOKED_FILE)
	if emp_id in revoked["revoked"]:
		print(f"{emp_id} already revoked")
		return
	revoked["revoked"].append(emp_id)
	save_json(REVOKED_FILE, revoked)
	print(f"✅ Employee {emp_id} revoked")
	push_updates_to_git()

def list_employees():
	public_keys = load_json(PUBLIC_KEYS_FILE)
	revoked = load_json(REVOKED_FILE)
	print("\nEmployee Directory:")
	for emp in public_keys:
		status = "❌ Revoked" if emp in revoked.get("revoked", []) else "✅ Active"
		print(f" - {emp}: {status}")

# ------------------------------
# CLI
# ------------------------------
def main():
	while True:
		print("\n=== Minecraft Store Pass Owner Tool ===")
		print("1. Add new employee")
		print("2. Revoke employee")
		print("3. List employees")
		print("4. Exit")
		choice = input("Select option: ").strip()
		if choice == "1":
			emp_id = input("Enter new employee ID: ").strip()
			add_employee(emp_id)
		elif choice == "2":
			emp_id = input("Enter employee ID to revoke: ").strip()
			revoke_employee(emp_id)
		elif choice == "3":
			list_employees()
		elif choice == "4":
			break
		else:
			print("Invalid choice")

if __name__ == "__main__":
	main()

