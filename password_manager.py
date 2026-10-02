# Local password manager
# Stores credentials encrypted on disk using AES, locked behind a master password
# Uses PBKDF2 to turn the master password into an actual encryption key (never store the password itself)

import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

DATA_FILE = "vault.json"
SALT_SIZE = 16
ITERATIONS = 200_000  # higher = slower to brute force, this is a reasonable modern value


def derive_key(master_password, salt):
    # turns the master password + salt into a proper encryption key
    # same password + same salt always produces the same key, which is what lets us decrypt later
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)  # Fernet needs the key in this specific format


def load_vault(master_password):
    # if there's no vault yet, we're creating a brand new one
    if not os.path.exists(DATA_FILE):
        salt = os.urandom(SALT_SIZE)
        key = derive_key(master_password, salt)
        vault = {"salt": base64.b64encode(salt).decode(), "entries": {}}
        save_vault(vault, key)
        return vault, key

    with open(DATA_FILE, "r") as f:
        raw = json.load(f)

    salt = base64.b64decode(raw["salt"])
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    # try decrypting the entries - if the master password is wrong, this will fail
    try:
        decrypted = fernet.decrypt(raw["entries"].encode()).decode()
        entries = json.loads(decrypted)
    except Exception:
        print("Wrong master password or corrupted vault.")
        exit(1)

    return {"salt": raw["salt"], "entries": entries}, key


def save_vault(vault, key):
    fernet = Fernet(key)
    entries_json = json.dumps(vault["entries"])
    encrypted_entries = fernet.encrypt(entries_json.encode()).decode()

    with open(DATA_FILE, "w") as f:
        json.dump({"salt": vault["salt"], "entries": encrypted_entries}, f)


def add_entry(vault, key):
    site = input("Site/service name: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()  # hides input while typing

    vault["entries"][site] = {"username": username, "password": password}
    save_vault(vault, key)
    print(f"Saved entry for {site}.")


def get_entry(vault):
    site = input("Site/service name to look up: ").strip()
    entry = vault["entries"].get(site)

    if entry:
        print(f"Site: {site}\nUsername: {entry['username']}\nPassword: {entry['password']}")
    else:
        print("No entry found for that site.")


def delete_entry(vault, key):
    site = input("Site/service name to delete: ").strip()

    if site in vault["entries"]:
        del vault["entries"][site]
        save_vault(vault, key)
        print(f"Deleted entry for {site}.")
    else:
        print("No entry found for that site.")


def search_entries(vault):
    term = input("Search term: ").strip().lower()
    matches = [site for site in vault["entries"] if term in site.lower()]

    if matches:
        print("Matches found:")
        for site in matches:
            print(f"  - {site}")
    else:
        print("No matches found.")


def main():
    print("=== Local Password Manager ===")
    master_password = getpass.getpass("Enter master password: ")

    vault, key = load_vault(master_password)

    while True:
        print("\n1. Add entry\n2. Get entry\n3. Delete entry\n4. Search entries\n5. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_entry(vault, key)
        elif choice == "2":
            get_entry(vault)
        elif choice == "3":
            delete_entry(vault, key)
        elif choice == "4":
            search_entries(vault)
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid option, try again.")


if __name__ == "__main__":
    main()