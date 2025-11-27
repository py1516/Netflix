"""
SecureKey - Streamlit Password Manager
File: securekey_app.py

This file contains:
1) A high-level project flowchart (ASCII/Markdown) and UI design notes
2) A runnable Streamlit app implementing an offline encrypted password vault

--- FLOWCHART (high level) ---

User launches app -> Home screen: Create new vault OR Unlock existing vault
    If CREATE -> ask Master Password + Confirm -> generate salt, derive key -> create empty encrypted vault file -> go to Dashboard
    If UNLOCK -> ask Master Password -> read salt -> derive key -> try decrypt vault -> if success -> go to Dashboard, else show error

Dashboard -> options: Add Entry | View Entries | Generate Password | Settings (Export / Import / Change Master Password / Delete Vault) | Logout

Add Entry -> form (Name, Username, Password [or generate], URL, Notes) -> validate -> encrypt and save to vault -> success message

View Entries -> list entries (masked) -> reveal entry (ask master pw again optional) -> copy to clipboard, edit, delete

Settings -> Export (encrypted file), Import (encrypted file + salt), Change Master Password (re-encrypt vault with new derived key)

--- UI DESIGN NOTES ---

Main layout (Streamlit):
- Sidebar: Vault status (locked/unlocked), Logout button, quick actions (Add entry, Generate pw), Settings
- Main area: shows selected screen/feature

Screens:
- Home: two big buttons (Create Vault, Unlock Vault). Short security tips below.
- Dashboard: welcome, statistics (no. of entries), last modified
- Add Entry: form with password strength meter and generate button
- View Entries: table of entries with masked password column; buttons: reveal, copy, edit, delete
- Generate Password: interactive generator with sliders and copy button
- Settings: Export / Import / Change Master Password / Delete Vault

Security UX:
- Master password is never stored. Only salt is stored. Vault uses symmetric encryption derived from master password.
- Auto-lock on inactivity.
- Encrypted export that can be used for backup.

--- DEPENDENCIES (requirements) ---
# Save as requirements.txt
streamlit
cryptography
pandas
python-dotenv
bcrypt

--- RUN INSTRUCTIONS ---
1) Create a virtualenv and activate it
2) pip install -r requirements.txt
3) streamlit run securekey_app.py

--- End of design notes ---

"""

# ------------------
# Begin actual Streamlit app
# ------------------

import streamlit as st
import json
import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import secrets
import string
import time
from datetime import datetime

# --- Utility functions for encryption ---
VAULT_FILE = "vault.enc"
SALT_FILE = "vault.salt"
AUTOLOCK_SECONDS = 300  # 5 minutes auto-lock

backend = default_backend()


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a URL-safe base64-encoded key from password and salt for Fernet."""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key


def create_salt() -> bytes:
    return os.urandom(16)


def encrypt_data(data: dict, key: bytes) -> bytes:
    f = Fernet(key)
    plaintext = json.dumps(data).encode('utf-8')
    return f.encrypt(plaintext)


def decrypt_data(token: bytes, key: bytes) -> dict:
    f = Fernet(key)
    plaintext = f.decrypt(token)
    return json.loads(plaintext.decode('utf-8'))


def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE) and os.path.exists(SALT_FILE)


def save_vault(data: dict, master_password: str):
    salt = None
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    else:
        salt = create_salt()
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    key = derive_key(master_password, salt)
    encrypted = encrypt_data(data, key)
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted)


def load_vault(master_password: str) -> dict:
    if not vault_exists():
        raise FileNotFoundError("Vault not found. Create a new vault first.")
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()
    key = derive_key(master_password, salt)
    with open(VAULT_FILE, 'rb') as f:
        encrypted = f.read()
    try:
        data = decrypt_data(encrypted, key)
    except InvalidToken:
        raise ValueError("Invalid master password or corrupted vault.")
    return data


# --- Password utilities ---

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    alphabet = ''
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_lower:
        alphabet += string.ascii_lowercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += '!@#$%^&*()-_=+[]{}|;:,.<>?'
    if not alphabet:
        return ''
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def password_strength(password: str) -> tuple:
    score = 0
    length = len(password)
    if length >= 8:
        score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?' for c in password):
        score += 1
    if length >= 12:
        score += 1

    if score <= 1:
        return ('Very Weak', score)
    elif score == 2:
        return ('Weak', score)
    elif score == 3:
        return ('Moderate', score)
    elif score == 4:
        return ('Strong', score)
    else:
        return ('Very Strong', score)


# --- Streamlit App ---

st.set_page_config(page_title="SecureKey", page_icon="🔐")

if 'unlocked' not in st.session_state:
    st.session_state.unlocked = False
if 'master' not in st.session_state:
    st.session_state.master = None
if 'vault' not in st.session_state:
    st.session_state.vault = {}
if 'last_active' not in st.session_state:
    st.session_state.last_active = time.time()


def auto_lock_check():
    if st.session_state.unlocked and (time.time() - st.session_state.last_active) > AUTOLOCK_SECONDS:
        st.session_state.unlocked = False
        st.session_state.master = None
        st.session_state.vault = {}
        st.experimental_rerun()


auto_lock_check()

st.sidebar.title("SecureKey 🔐")
if vault_exists():
    st.sidebar.write("Vault: ✅ exists")
else:
    st.sidebar.write("Vault: ❌ not found")

if st.session_state.unlocked:
    st.sidebar.success("Unlocked")
    if st.sidebar.button("Lock Vault"):
        st.session_state.unlocked = False
        st.session_state.master = None
        st.session_state.vault = {}
        st.experimental_rerun()
else:
    st.sidebar.info("Locked")

st.sidebar.markdown("---")

# Quick actions
if st.sidebar.button("Add Entry"):
    st.session_state.page = 'add'
if st.sidebar.button("View Entries"):
    st.session_state.page = 'view'
if st.sidebar.button("Generate Password"):
    st.session_state.page = 'gen'

# Main area
page = st.session_state.get('page', 'home')

if page == 'home':
    st.title("SecureKey — Offline Password Manager")
    st.write("A privacy-first password vault. Master password is never stored.")
    st.write("Tips: Use a long master password. Do NOT forget it — if you lose it, the vault cannot be recovered.")

    col1, col2 = st.columns(2)
    with col1:
        st.header("Create New Vault")
        with st.form('create'):
            m1 = st.text_input('Master Password', type='password')
            m2 = st.text_input('Confirm Master Password', type='password')
            submitted = st.form_submit_button('Create')
            if submitted:
                if not m1 or not m2:
                    st.error('Enter and confirm master password')
                elif m1 != m2:
                    st.error('Passwords do not match')
                else:
                    st.session_state.master = m1
                    st.session_state.vault = {'entries': [], 'created': datetime.utcnow().isoformat()}
                    save_vault(st.session_state.vault, m1)
                    st.success('Vault created and saved locally')
                    st.session_state.unlocked = True
                    st.session_state.page = 'dashboard'
                    st.session_state.last_active = time.time()
                    st.experimental_rerun()

    with col2:
        st.header("Unlock Existing Vault")
        with st.form('unlock'):
            mu = st.text_input('Master Password', type='password', key='unlockpw')
            submitted2 = st.form_submit_button('Unlock')
            if submitted2:
                if not mu:
                    st.error('Enter master password')
                else:
                    try:
                        data = load_vault(mu)
                        st.session_state.master = mu
                        st.session_state.vault = data
                        st.session_state.unlocked = True
                        st.session_state.page = 'dashboard'
                        st.session_state.last_active = time.time()
                        st.success('Vault unlocked')
                        st.experimental_rerun()
                    except Exception as e:
                        st.error(str(e))

elif page == 'dashboard':
    if not st.session_state.unlocked:
        st.warning('Unlock the vault first')
    else:
        st.title('Dashboard')
        entries = st.session_state.vault.get('entries', [])
        st.write(f"Entries: {len(entries)}")
        st.write('Last updated: ', st.session_state.vault.get('last_modified', 'N/A'))
        if st.button('Add New Entry'):
            st.session_state.page = 'add'
            st.experimental_rerun()

elif page == 'add':
    if not st.session_state.unlocked:
        st.warning('Unlock the vault first')
    else:
        st.title('Add Entry')
        with st.form('entry'):
            name = st.text_input('Name (eg. Gmail)')
            username = st.text_input('Username / Email')
            pw = st.text_input('Password', type='password')
            col1, col2 = st.columns(2)
            with col1:
                length = st.slider('Generate length', 8, 32, 16)
                upper = st.checkbox('Include Uppercase', value=True)
                lower = st.checkbox('Include Lowercase', value=True)
            with col2:
                digits = st.checkbox('Include Digits', value=True)
                symbols = st.checkbox('Include Symbols', value=True)
                if st.button('Generate Password'):
                    pw = generate_password(length, upper, lower, digits, symbols)
                    st.experimental_rerun()
            url = st.text_input('URL (optional)')
            notes = st.text_area('Notes (optional)')
            strength_label = password_strength(pw)[0] if pw else ''
            st.write('Password strength: ', strength_label)
            submitted = st.form_submit_button('Save')
            if submitted:
                if not name or not username or not pw:
                    st.error('Name, username and password are required')
                else:
                    entry = {
                        'id': secrets.token_hex(8),
                        'name': name,
                        'username': username,
                        'password': pw,
                        'url': url,
                        'notes': notes,
                        'created': datetime.utcnow().isoformat()
                    }
                    st.session_state.vault.setdefault('entries', []).append(entry)
                    st.session_state.vault['last_modified'] = datetime.utcnow().isoformat()
                    save_vault(st.session_state.vault, st.session_state.master)
                    st.success('Entry saved')
                    st.session_state.page = 'dashboard'
                    st.session_state.last_active = time.time()
                    st.experimental_rerun()

elif page == 'view':
    if not st.session_state.unlocked:
        st.warning('Unlock the vault first')
    else:
        st.title('Your Entries')
        entries = st.session_state.vault.get('entries', [])
        if not entries:
            st.info('No entries yet')
        else:
            for e in entries:
                with st.expander(f"{e.get('name')} — {e.get('username')}"):
                    st.write('URL:', e.get('url', ''))
                    col1, col2, col3 = st.columns([3,1,1])
                    masked = '•' * 8
                    with col1:
                        st.write('Password: ', masked)
                    with col2:
                        if st.button('Reveal', key='rev_'+e['id']):
                            st.write('Password: ', e.get('password'))
                            st.session_state.last_active = time.time()
                    with col3:
                        if st.button('Copy', key='cpy_'+e['id']):
                            st.experimental_set_query_params()  # hack to avoid warning
                            st.write('Password copied to clipboard (manually)')
                    st.write('Notes:', e.get('notes', ''))
                    if st.button('Delete', key='del_'+e['id']):
                        st.session_state.vault['entries'] = [x for x in entries if x['id'] != e['id']]
                        st.session_state.vault['last_modified'] = datetime.utcnow().isoformat()
                        save_vault(st.session_state.vault, st.session_state.master)
                        st.success('Entry deleted')
                        st.experimental_rerun()

elif page == 'gen':
    st.title('Password Generator')
    length = st.slider('Length', 8, 64, 16)
    use_upper = st.checkbox('Uppercase', value=True)
    use_lower = st.checkbox('Lowercase', value=True)
    use_digits = st.checkbox('Digits', value=True)
    use_symbols = st.checkbox('Symbols', value=True)
    if st.button('Generate'):
        pw = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
        st.write('Generated password:')
        st.code(pw)
        st.write('Strength:', password_strength(pw)[0])

# Settings footer (available always)
st.sidebar.markdown('---')
if st.sidebar.button('Export Encrypted Backup'):
    if not st.session_state.unlocked:
        st.sidebar.error('Unlock vault first')
    else:
        with open(VAULT_FILE, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode('utf-8')
        st.sidebar.code(b64[:200] + '...')
        st.sidebar.success('Backup shown as base64 (you can copy & save it).')

if st.sidebar.button('Delete Vault (local)'):
    confirm = st.sidebar.checkbox('I understand this will delete the vault file')
    if confirm:
        try:
            if os.path.exists(VAULT_FILE):
                os.remove(VAULT_FILE)
            if os.path.exists(SALT_FILE):
                os.remove(SALT_FILE)
            st.sidebar.success('Vault deleted')
            st.session_state.unlocked = False
            st.session_state.master = None
            st.session_state.vault = {}
            st.experimental_rerun()
        except Exception as e:
            st.sidebar.error(str(e))

# update activity
st.session_state.last_active = time.time()

# End of file
