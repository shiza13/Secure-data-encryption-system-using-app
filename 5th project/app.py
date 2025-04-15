import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

DATA_FILE = "encrypted_data.json"
USERS_FILE = "users.json"
LOCKOUT_DURATION = 30
MAX_LOGIN_ATTEMPTS = 3
MASTER_PASSWORD = "master123"

def get_encryption_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)
    return key

KEY = get_encryption_key()
cipher = Fernet(KEY)

if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = {}
if 'last_encrypted_data' not in st.session_state:
    st.session_state.last_encrypted_data = None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(token):
    try:
        return cipher.decrypt(token.encode()).decode()
    except:
        return None

def load_data(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    return {}

def save_data(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

users = load_data(USERS_FILE)
stored = load_data(DATA_FILE)

def home():
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
    Welcome to the Secure Data Encryption System — your personal tool for safely encrypting and decrypting sensitive information.  
    🛡️ Features include:
    - User registration and login with secure password hashing  
    - Lockout system after multiple failed attempts  
    - Data encryption using the Fernet encryption method  
    - Admin override with a master password  
    - Encrypted data retrieval and session storage  

    Enjoy a secure experience while keeping your data safe!
    """)
    st.markdown("<br><br><center><b>Created by Shiza Tariq</b></center>", unsafe_allow_html=True)

def register():
    st.subheader("🧑‍💻 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username in users:
            st.error("Username already exists.")
        else:
            users[username] = hash_password(password)
            save_data(users, USERS_FILE)
            st.success("User registered successfully!")

def login():
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if username in st.session_state.lockout_until:
        if time.time() < st.session_state.lockout_until[username]:
            wait = int(st.session_state.lockout_until[username] - time.time())
            st.warning(f"Account locked. Try again in {wait} seconds.")
            return

    if st.button("Login"):
        if username in users and users[username] == hash_password(password):
            st.session_state.current_user = username
            st.session_state.failed_attempts[username] = 0
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials.")
            st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
            if st.session_state.failed_attempts[username] >= MAX_LOGIN_ATTEMPTS:
                st.session_state.lockout_until[username] = time.time() + LOCKOUT_DURATION
                st.warning(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION} seconds.")

def store_data():
    if not st.session_state.current_user:
        st.warning("Please log in first.")
        return

    st.subheader("📦 Store Data")
    content = st.text_area("Enter data to encrypt")

    if st.button("Encrypt and Save"):
        if content:
            encrypted = encrypt(content)
            stored[encrypted] = { "owner": st.session_state.current_user }
            save_data(stored, DATA_FILE)
            st.session_state.last_encrypted_data = encrypted
            st.success("Data encrypted and stored successfully!")
            st.text_area("Your Encrypted Data", encrypted, height=100)
        else:
            st.error("Please enter some data.")

def retrieve_data():
    if not st.session_state.current_user:
        st.warning("Please log in first.")
        return

    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Paste Encrypted Data")

    if st.button("Decrypt"):
        result = decrypt(encrypted_input)
        if result:
            if encrypted_input in stored and stored[encrypted_input]["owner"] == st.session_state.current_user:
                st.success("Data decrypted successfully!")
                st.text_area("Decrypted Data", result, height=100)
            else:
                st.error("Unauthorized access or data not found.")
        else:
            st.error("Decryption failed. Ensure data is valid.")

def retrieve_last_key():
    if not st.session_state.current_user:
        st.warning("Please log in first.")
        return

    st.subheader("🔁 Retrieve Last Encrypted Key")
    password = st.text_input("Re-enter your password to unlock key", type="password")

    if st.button("Show Last Encrypted Key"):
        if users.get(st.session_state.current_user) == hash_password(password):
            last_key = st.session_state.get("last_encrypted_data")
            if last_key:
                st.success("Here is your last encrypted key:")
                st.text_area("Last Encrypted Key", last_key, height=100)
            else:
                st.warning("No recently stored encrypted key found in this session.")
        else:
            st.error("Incorrect password.")

def master_login():
    st.subheader("🔐 Admin Reauthorization")
    password = st.text_input("Enter Master Password", type="password")

    if st.button("Authorize"):
        if password == MASTER_PASSWORD:
            st.success("Master access granted.")
            st.session_state.failed_attempts = {}
            st.session_state.lockout_until = {}
        else:
            st.error("Incorrect master password.")

pages = [
    "Home",
    "Register",
    "Login",
    "Store Data",
    "Retrieve Data",
    "Retrieve Key",
    "Master Login"
]

selected = st.sidebar.selectbox("Navigation", pages)

if selected == "Home":
    home()
elif selected == "Register":
    register()
elif selected == "Login":
    login()
elif selected == "Store Data":
    store_data()
elif selected == "Retrieve Data":
    retrieve_data()
elif selected == "Retrieve Key":
    retrieve_last_key()
elif selected == "Master Login":
    master_login()

save_data(users, USERS_FILE)
save_data(stored, DATA_FILE)
