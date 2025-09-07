#!/usr/bin/env python3
# tabs-only indentation
import os
import sys
import json
import base64
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "data.json"

def load_data():
	if not DATA_FILE.exists():
		return {"public_keys": {}, "revoked": []}
	with open(DATA_FILE, "r") as f:
		return json.load(f)

def save_data(data):
	with open(DATA_FILE, "w") as f:
		json.dump(data, f, indent=4)

def push_updates_to_git():
	subprocess.run(["git", "add", str(DATA_FILE)], check=True)
	subprocess.run(["git", "commit", "-m", "Update data.json"], check=True)
	subprocess.run(["git", "push"], check=True)

def add_employee(emp_id: str):
	private_key = ed25519.Ed25519PrivateKey.generate()
	public_key = private_key.public_key()

	pub_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw
	)
	priv_bytes = private_key.private_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PrivateFormat.Raw,
		encryption_algorithm=serialization.NoEncryption()
	)

	data = load_data()
	if emp_id in data["public_keys"]:
		print(f"⚠️ Employee {emp_id} already exists!")
		return

	data["public_keys"][emp_id] = base64.b64encode(pub_bytes).decode("utf-8")
	save_data(data)
	print(f"✅ Employee {emp_id} added!")
	print("Send PRIVATE key to employee:")
	print(base64.b64encode(priv_bytes).decode("utf-8"))

	push_updates_to_git()

def revoke_employee(emp_id: str):
	data = load_data()
	if emp_id not in data["public_keys"]:
		print("❌ Employee not found")
		return
	if emp_id in data["revoked"]:
		print("⚠️ Already revoked")
		return

	data["revoked"].append(emp_id)
	save_data(data)
	print(f"❌ Employee {emp_id} revoked")

	push_updates_to_git()

def list_employees():
	data = load_data()
	print("=== Employees ===")
	for emp_id, pub in data["public_keys"].items():
		status = "REVOKED" if emp_id in data["revoked"] else "ACTIVE"
		print(f"- ID: {emp_id} | {status}")

def main():
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
	else:
		sys.exit(0)

if __name__ == "__main__":
	while True:
		main()

