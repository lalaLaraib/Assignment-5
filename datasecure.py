# 🛡️ Python Assignment: Secure Data Encryption System Using Streamlit
import streamlit as st
import hashlib
from cryptography.fernet import Fernet 


if "stored_data" not in st.session_state:
    st.session_state["stored_data"] = {}

if "users" not in st.session_state:
    st.session_state["users"] = {}

if "cipher" not in st.session_state:
    key = Fernet.generate_key()
    st.session_state["cipher"] = Fernet(key)

# --- Helper Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    return stored_hash == hash_password(password)

def encrypt_text(text):
    return st.session_state["cipher"].encrypt(text.encode()).decode()

def decrypt_text(encrypted):
    return st.session_state["cipher"].decrypt(encrypted.encode()).decode()

# --- Login Page ---
def login_page():
    st.title("🔐 Login")
    username = st.text_input("Enter your username:")
    password = st.text_input("Enter your password:", type="password")

    if st.button("Login"):
        if not username or not password:
            st.error("Both username and password are required!")
        elif username and password:
            st.session_state["auth"] = True
            st.success(f"Login successful! Welcome, {username}.")
        else:
            st.error("Incorrect username or password!")

# --- Store Data Page ---
def store_data_page():
    st.title("📦 STORE SECURE DATA")
    username = st.text_input("Username:")
    text = st.text_area("Enter text to store:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Store"):
        if username and text and passkey:
            hashed = hash_password(passkey)
            encrypted = encrypt_text(text)
            st.session_state["stored_data"][username] = {
                "encrypted_text": encrypted,
                "passkey": hashed,
                "failed_attempts": 0
            }
            st.success("Data stored successfully!")
        else:
            st.warning("Please fill all fields!")

# --- Retrieve Data Page ---
def retrieve_data_page():
    st.title("🔓 RETRIEVE SECURE DATA")
    username = st.text_input("Username:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Retrieve"):
        stored_data = st.session_state["stored_data"]
        if username in stored_data:
            user_data = stored_data[username]
            if user_data["failed_attempts"] >= 3:
                st.warning("Too many failed attempts! Please login again.")
                st.session_state["auth"] = False
                return

            if hash_password(passkey) == user_data["passkey"]:
                decrypted = decrypt_text(user_data["encrypted_text"])
                st.success(f"Decrypted Data: {decrypted}")
                user_data["failed_attempts"] = 0
            else:
                user_data["failed_attempts"] += 1
                st.error("Incorrect passkey!")
                st.info(f"Attempts left: {3 - user_data['failed_attempts']}")
        else:
            st.error("User not found!")

# --- Logout Function ---
def logout():
    st.session_state["auth"] = False
    st.session_state.clear()
    st.success("You have logged out.")

# --- Main ---
def main():
    if "auth" not in st.session_state:
        st.session_state["auth"] = False

    if not st.session_state["auth"]:
        login_page()
    else:
        choice = st.sidebar.radio("Go to", ["Home", "Store", "Retrieve", "Logout"])

        if choice == "Home":
            st.title("🛡️ SECURE DATA ENCRYPTION SYSTEM")
            st.write("Use the sidebar to store or retrieve encrypted data.")
        elif choice == "Store":
            store_data_page()
        elif choice == "Retrieve":
            retrieve_data_page()
        elif choice == "Logout":
            logout()

main()
