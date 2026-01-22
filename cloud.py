import streamlit as st
import os
import json
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import uuid

# ============== CONFIGURATION ==============
STORAGE_DIR = Path("cloud_storage")
METADATA_DIR = STORAGE_DIR / "metadata"
USERS_FILE = STORAGE_DIR / "users.json"
SHARES_FILE = STORAGE_DIR / "shares.json"
OAUTH_TOKENS_FILE = STORAGE_DIR / "oauth_tokens.json"

# Create directories
STORAGE_DIR.mkdir(exist_ok=True)
METADATA_DIR.mkdir(exist_ok=True)

# ============== UTILITY FUNCTIONS ==============

def init_files():
    """Initialize storage files if they don't exist"""
    if not USERS_FILE.exists():
        USERS_FILE.write_text(json.dumps({}))
    if not SHARES_FILE.exists():
        SHARES_FILE.write_text(json.dumps({}))
    if not OAUTH_TOKENS_FILE.exists():
        OAUTH_TOKENS_FILE.write_text(json.dumps({}))

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users() -> dict:
    """Load users from file"""
    try:
        return json.loads(USERS_FILE.read_text())
    except:
        return {}

def save_users(users: dict):
    """Save users to file"""
    USERS_FILE.write_text(json.dumps(users, indent=2))

def load_shares() -> dict:
    """Load sharing data"""
    try:
        return json.loads(SHARES_FILE.read_text())
    except:
        return {}

def save_shares(shares: dict):
    """Save sharing data"""
    SHARES_FILE.write_text(json.dumps(shares, indent=2))

def load_oauth_tokens() -> dict:
    """Load OAuth tokens"""
    try:
        return json.loads(OAUTH_TOKENS_FILE.read_text())
    except:
        return {}

def save_oauth_tokens(tokens: dict):
    """Save OAuth tokens"""
    OAUTH_TOKENS_FILE.write_text(json.dumps(tokens, indent=2))

def generate_oauth_code() -> str:
    """Generate OAuth authorization code"""
    return secrets.token_urlsafe(32)

def generate_access_token(user_id: str) -> str:
    """Generate access token"""
    return secrets.token_urlsafe(32)

def register_user(username: str, email: str, password: str) -> bool:
    """Register a new user"""
    users = load_users()
    if username in users:
        return False
    
    users[username] = {
        "email": email,
        "password": hash_password(password),
        "created": datetime.now().isoformat(),
        "storage_used": 0
    }
    save_users(users)
    return True

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user credentials"""
    users = load_users()
    if username not in users:
        return False
    return users[username]["password"] == hash_password(password)

def get_user_storage_path(username: str) -> Path:
    """Get storage path for user"""
    user_path = STORAGE_DIR / username
    user_path.mkdir(exist_ok=True)
    return user_path

def get_file_versions(username: str, filename: str) -> list:
    """Get all versions of a file"""
    user_path = get_user_storage_path(username)
    versions = []
    
    # Find all version files
    for file in user_path.glob(f"{filename}.v*"):
        version_num = file.stem.split('v')[1]
        versions.append({
            "version": version_num,
            "path": file,
            "size": file.stat().st_size,
            "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
        })
    
    return sorted(versions, key=lambda x: int(x["version"]), reverse=True)

def upload_file(username: str, file_data, filename: str):
    """Upload file with versioning"""
    user_path = get_user_storage_path(username)
    
    # Find next version number
    versions = get_file_versions(username, filename)
    next_version = 1 if not versions else int(versions[0]["version"]) + 1
    
    # Save versioned file
    versioned_name = f"{filename}.v{next_version}"
    file_path = user_path / versioned_name
    
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    # Update metadata
    users = load_users()
    users[username]["storage_used"] = sum(
        f.stat().st_size for f in user_path.glob("*") if f.is_file()
    )
    save_users(users)
    
    return next_version

def list_files(username: str) -> list:
    """List all files for user (latest versions only)"""
    user_path = get_user_storage_path(username)
    files = {}
    
    for file in user_path.glob("*.v*"):
        base_name = file.stem.rsplit('.v', 1)[0]
        version = int(file.stem.rsplit('.v', 1)[1])
        
        if base_name not in files or version > files[base_name]["version"]:
            files[base_name] = {
                "filename": base_name,
                "version": version,
                "path": file,
                "size": file.stat().st_size,
                "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
            }
    
    return sorted(files.values(), key=lambda x: x["modified"], reverse=True)

def share_file(username: str, filename: str, share_with: str, permission: str = "view"):
    """Share a file with another user"""
    shares = load_shares()
    share_id = str(uuid.uuid4())
    
    shares[share_id] = {
        "from": username,
        "to": share_with,
        "file": filename,
        "permission": permission,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(days=30)).isoformat()
    }
    
    save_shares(shares)
    return share_id

def get_shared_files(username: str) -> list:
    """Get files shared with user"""
    shares = load_shares()
    shared = []
    
    for share_id, share_data in shares.items():
        if share_data["to"] == username:
            # Check if not expired
            expires = datetime.fromisoformat(share_data["expires"])
            if expires > datetime.now():
                shared.append({
                    "file": share_data["file"],
                    "from": share_data["from"],
                    "permission": share_data["permission"],
                    "share_id": share_id
                })
    
    return shared

def download_file(username: str, filename: str, version: int = None):
    """Download file"""
    user_path = get_user_storage_path(username)
    
    if version:
        file_path = user_path / f"{filename}.v{version}"
    else:
        versions = get_file_versions(username, filename)
        if not versions:
            return None
        file_path = versions[0]["path"]
    
    if file_path.exists():
        return file_path.read_bytes()
    return None

def delete_file(username: str, filename: str):
    """Delete all versions of a file"""
    user_path = get_user_storage_path(username)
    for file in user_path.glob(f"{filename}.v*"):
        file.unlink()

# ============== STREAMLIT APP ==============

st.set_page_config(page_title="Cloud Storage", layout="wide")

# Initialize
init_files()

# Session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"

# ============== UI ==============

st.title("☁️ Cloud Storage System")

if not st.session_state.logged_in:
    st.subheader("Authentication")
    
    auth_mode = st.radio("Select Mode", ["Login", "Register"], horizontal=True)
    
    if auth_mode == "Register":
        st.write("### Create New Account")
        reg_user = st.text_input("Username", placeholder="Choose a username")
        reg_email = st.text_input("Email", placeholder="your@email.com")
        reg_pass = st.text_input("Password", type="password", placeholder="Enter password")
        
        if st.button("Create Account", type="primary"):
            if not reg_user or not reg_email or not reg_pass:
                st.error("❌ Please fill in all fields")
            elif len(reg_user) < 3:
                st.error("❌ Username must be at least 3 characters")
            elif len(reg_pass) < 4:
                st.error("❌ Password must be at least 4 characters")
            elif register_user(reg_user, reg_email, reg_pass):
                st.success("✅ Registration successful! Now login with your credentials.")
            else:
                st.error("❌ Username already exists. Choose a different one.")
    
    else:
        st.write("### Login to Your Account")
        login_user = st.text_input("Username", placeholder="Enter your username")
        login_pass = st.text_input("Password", type="password", placeholder="Enter your password")
        
        if st.button("Login", type="primary"):
            if not login_user or not login_pass:
                st.error("❌ Please enter both username and password")
            elif authenticate_user(login_user, login_pass):
                st.session_state.logged_in = True
                st.session_state.username = login_user
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password. Please check and try again.")

else:
    st.sidebar.success(f"✅ Logged in as: {st.session_state.username}")
    
    users = load_users()
    storage_used = users[st.session_state.username]["storage_used"]
    st.sidebar.metric("Storage Used", f"{storage_used / 1024:.2f} KB")
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["📁 My Files", "🔗 Shared Files", "📤 Upload"])
    
    with tab1:
        st.subheader("My Files")
        files = list_files(st.session_state.username)
        
        if not files:
            st.info("No files yet. Upload one to get started!")
        else:
            for file in files:
                col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                
                with col1:
                    st.write(f"📄 **{file['filename']}**")
                    st.caption(f"v{file['version']} | {file['size']} bytes | {file['modified']}")
                
                with col2:
                    if st.button("⬇️ Download", key=f"dl_{file['filename']}"):
                        data = download_file(st.session_state.username, file['filename'])
                        st.download_button(
                            "Save File",
                            data,
                            file_name=file['filename'],
                            key=f"save_{file['filename']}"
                        )
                
                with col3:
                    if st.button("📋 Versions", key=f"ver_{file['filename']}"):
                        st.session_state[f"show_versions_{file['filename']}"] = True
                
                with col4:
                    if st.button("🗑️ Delete", key=f"del_{file['filename']}"):
                        delete_file(st.session_state.username, file['filename'])
                        st.rerun()
                
                # Show versions
                if st.session_state.get(f"show_versions_{file['filename']}", False):
                    versions = get_file_versions(st.session_state.username, file['filename'])
                    st.write("**Versions:**")
                    for v in versions:
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            st.caption(f"v{v['version']} | {v['modified']}")
                        with col2:
                            if st.button("Restore", key=f"restore_{file['filename']}_v{v['version']}"):
                                data = download_file(st.session_state.username, file['filename'], int(v['version']))
                                upload_file(st.session_state.username, data, file['filename'])
                                st.success("Version restored!")
                                st.rerun()
                
                # Share options
                st.write("**Share with:**")
                share_user = st.text_input(f"Username", key=f"share_{file['filename']}")
                share_perm = st.selectbox("Permission", ["view", "download"], key=f"perm_{file['filename']}")
                
                if st.button("Share", key=f"share_btn_{file['filename']}"):
                    share_file(st.session_state.username, file['filename'], share_user, share_perm)
                    st.success(f"✅ Shared with {share_user}!")
                
                st.divider()
    
    with tab2:
        st.subheader("Shared with Me")
        shared = get_shared_files(st.session_state.username)
        
        if not shared:
            st.info("No files shared with you yet.")
        else:
            for item in shared:
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    st.write(f"📄 **{item['file']}** (from {item['from']})")
                    st.caption(f"Permission: {item['permission']}")
                
                with col2:
                    if item['permission'] in ['download', 'view']:
                        if st.button("⬇️ Download", key=f"shared_dl_{item['share_id']}"):
                            data = download_file(item['from'], item['file'])
                            st.download_button(
                                "Save File",
                                data,
                                file_name=item['file'],
                                key=f"shared_save_{item['share_id']}"
                            )
                
                st.divider()
    
    with tab3:
        st.subheader("Upload File")
        uploaded_file = st.file_uploader("Choose a file")
        
        if uploaded_file is not None:
            if st.button("Upload"):
                version = upload_file(st.session_state.username, uploaded_file.getvalue(), uploaded_file.name)
                st.success(f"✅ File uploaded! (v{version})")
                st.rerun()