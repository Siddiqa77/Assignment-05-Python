import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # seconds
MAX_ATTEMPTS = 3

# === Session State Initialization ===
for key, value in {
    "authenticated_user": None,
    "failed_attempts": 0,
    "lockout_time": 0
}.items():
    if key not in st.session_state:
        st.session_state[key] = value

# === Utility Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key).ljust(32, b'=')

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.encrypt(text.encode()).decode()
    except Exception:
        return None

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except (InvalidToken, Exception):
        return None

# === Load Data ===
stored_data = load_data()

# === UI Layout ===
st.set_page_config(page_title="Secure Encryption App", page_icon="🔐")
st.title("🔐 Secure Data Encryption App")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "📁 Store Data", "🔍 Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

# === Pages ===
if choice == "🏠 Home":
    st.subheader("Welcome! ✨")
    st.markdown("""
    This app helps you securely:
    - Register/Login with encrypted credentials
    - Store and retrieve encrypted data
    - Protects your account with a lockout after 3 failed attempts 🔒
    """)

elif choice == "📝 Register":
    st.subheader("Create an Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists. Try logging in.")
            else:
                stored_data[username] = {"password": hash_password(password), "data": []}
                save_data(stored_data)
                st.success("✅ Registered successfully! You can now login.")
        else:
            st.error("Please fill out all fields.")

elif choice == "🔑 Login":
    st.subheader("Access Your Account")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Locked out due to multiple failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Logged in as {username}")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚫 Too many attempts! You are locked out for 60 seconds.")
                st.stop()

elif choice == "📁 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login to store data.")
    else:
        st.subheader("Encrypt & Store Data")
        raw_data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key", type="password")

        if st.button("Encrypt & Save"):
            if raw_data and passkey:
                encrypted = encrypt_text(raw_data, passkey)
                if encrypted:
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and stored!")
                else:
                    st.error("Encryption failed.")
            else:
                st.error("Both fields are required.")

elif choice == "🔍 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login to retrieve data.")
    else:
        st.subheader("View & Decrypt Stored Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No encrypted data found.")
        else:
            st.markdown("### 🔐 Stored Encrypted Entries")
            for i, item in enumerate(user_data, start=1):
                st.code(item, language="text")

            encrypted_input = st.text_area("Paste an encrypted entry to decrypt")
            passkey = st.text_input("Decryption Key", type="password")

            if st.button("🔓 Decrypt"):
                if encrypted_input and passkey:
                    decrypted = decrypt_text(encrypted_input, passkey)
                    if decrypted:
                        st.success(f"✅ Decrypted Result:\n\n`{decrypted}`")
                    else:
                        st.error("❌ Incorrect key or invalid encrypted text.")
                else:
                    st.error("Both fields are required.")

            # Optional: Delete all stored data
            if st.button("🗑️ Delete All My Data"):
                stored_data[st.session_state.authenticated_user]["data"] = []
                save_data(stored_data)
                st.success("✅ All your encrypted data has been deleted.")
