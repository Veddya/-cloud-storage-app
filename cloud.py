import streamlit as st
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import mimetypes
from io import BytesIO
import pandas as pd

# ============== PAGE CONFIG ==============
st.set_page_config(
    page_title="CloudDrive - Secure Cloud Storage",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============== CUSTOM CSS ==============
st.markdown("""
<style>
    [data-testid="stSidebar"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .main {
        background-color: #f5f7fa;
    }
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .file-item {
        background: white;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #667eea;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# ============== CONFIGURATION ==============
STORAGE_DIR = Path("cloud_storage")
METADATA_DIR = STORAGE_DIR / "metadata"
USERS_FILE = STORAGE_DIR / "users.json"
SHARES_FILE = STORAGE_DIR / "shares.json"
RECYCLE_BIN_FILE = STORAGE_DIR / "recycle_bin.json"
ACTIVITY_LOG_FILE = STORAGE_DIR / "activity_log.json"

STORAGE_QUOTA = 5 * 1024 * 1024 * 1024  # 5GB per user

# Create directories
for dir_path in [STORAGE_DIR, METADATA_DIR]:
    dir_path.mkdir(exist_ok=True)

# ============== UTILITY FUNCTIONS ==============

def init_files():
    """Initialize storage files"""
    for file_path in [USERS_FILE, SHARES_FILE, RECYCLE_BIN_FILE, ACTIVITY_LOG_FILE]:
        if not file_path.exists():
            file_path.write_text(json.dumps({}))

def hash_password(password: str) -> str:
    """Hash password"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_json(file_path: Path) -> dict:
    """Load JSON file"""
    try:
        return json.loads(file_path.read_text())
    except:
        return {}

def save_json(file_path: Path, data: dict):
    """Save JSON file"""
    file_path.write_text(json.dumps(data, indent=2))

def log_activity(username: str, action: str, details: str):
    """Log user activity"""
    logs = load_json(ACTIVITY_LOG_FILE)
    log_id = str(uuid.uuid4())
    logs[log_id] = {
        "username": username,
        "action": action,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }
    save_json(ACTIVITY_LOG_FILE, logs)

def register_user(username: str, email: str, password: str) -> bool:
    """Register new user"""
    users = load_json(USERS_FILE)
    if username in users:
        return False
    
    users[username] = {
        "email": email,
        "password": hash_password(password),
        "created": datetime.now().isoformat(),
        "storage_used": 0,
        "plan": "free",
        "profile_pic": None,
        "settings": {
            "theme": "light",
            "notifications": True,
            "two_factor": False
        }
    }
    save_json(USERS_FILE, users)
    log_activity(username, "REGISTER", "New account created")
    return True

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user"""
    users = load_json(USERS_FILE)
    if username not in users:
        return False
    return users[username]["password"] == hash_password(password)

def get_user_storage_path(username: str) -> Path:
    """Get user storage path"""
    user_path = STORAGE_DIR / username
    user_path.mkdir(exist_ok=True)
    return user_path

def get_file_icon(filename: str) -> str:
    """Get file type icon"""
    ext = Path(filename).suffix.lower()
    icons = {
        '.pdf': '📄',
        '.doc': '📝',
        '.docx': '📝',
        '.xls': '📊',
        '.xlsx': '📊',
        '.ppt': '📑',
        '.pptx': '📑',
        '.jpg': '🖼️',
        '.jpeg': '🖼️',
        '.png': '🖼️',
        '.gif': '🖼️',
        '.mp4': '🎥',
        '.avi': '🎥',
        '.mp3': '🎵',
        '.wav': '🎵',
        '.zip': '📦',
        '.rar': '📦',
        '.txt': '📄',
        '.csv': '📊',
    }
    return icons.get(ext, '📁')

def upload_file(username: str, file_data, filename: str, file_type: str = None):
    """Upload file with versioning"""
    user_path = get_user_storage_path(username)
    
    # Get next version
    versions = get_file_versions(username, filename)
    next_version = 1 if not versions else int(versions[0]["version"]) + 1
    
    versioned_name = f"{filename}.v{next_version}"
    file_path = user_path / versioned_name
    
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    # Update storage
    users = load_json(USERS_FILE)
    users[username]["storage_used"] = sum(
        f.stat().st_size for f in user_path.glob("*") if f.is_file()
    )
    save_json(USERS_FILE, users)
    
    log_activity(username, "UPLOAD", f"Uploaded {filename}")
    return next_version

def get_file_versions(username: str, filename: str) -> list:
    """Get all file versions"""
    user_path = get_user_storage_path(username)
    versions = []
    
    for file in user_path.glob(f"{filename}.v*"):
        version_num = file.stem.split('v')[1]
        versions.append({
            "version": version_num,
            "path": file,
            "size": file.stat().st_size,
            "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
        })
    
    return sorted(versions, key=lambda x: int(x["version"]), reverse=True)

def list_files(username: str) -> list:
    """List latest file versions"""
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
                "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                "icon": get_file_icon(base_name)
            }
    
    return sorted(files.values(), key=lambda x: x["modified"], reverse=True)

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
    """Move to recycle bin"""
    trash = load_json(RECYCLE_BIN_FILE)
    trash_id = str(uuid.uuid4())
    
    trash[trash_id] = {
        "username": username,
        "filename": filename,
        "deleted_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=30)).isoformat()
    }
    save_json(RECYCLE_BIN_FILE, trash)
    
    user_path = get_user_storage_path(username)
    for file in user_path.glob(f"{filename}.v*"):
        file.unlink()
    
    log_activity(username, "DELETE", f"Deleted {filename}")

def permanently_delete_file(username: str, filename: str):
    """Permanently delete file"""
    user_path = get_user_storage_path(username)
    for file in user_path.glob(f"{filename}.v*"):
        file.unlink()
    log_activity(username, "PERMANENT_DELETE", f"Permanently deleted {filename}")

def restore_from_trash(username: str, trash_id: str):
    """Restore file from trash"""
    trash = load_json(RECYCLE_BIN_FILE)
    if trash_id not in trash:
        return False
    
    del trash[trash_id]
    save_json(RECYCLE_BIN_FILE, trash)
    log_activity(username, "RESTORE", "Restored file from trash")
    return True

def share_file(username: str, filename: str, share_with: str, permission: str = "view") -> str:
    """Share file"""
    shares = load_json(SHARES_FILE)
    share_id = str(uuid.uuid4())
    
    shares[share_id] = {
        "from": username,
        "to": share_with,
        "file": filename,
        "permission": permission,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(days=30)).isoformat(),
        "link": f"share/{share_id}"
    }
    
    save_json(SHARES_FILE, shares)
    log_activity(username, "SHARE", f"Shared {filename} with {share_with}")
    return share_id

def get_shared_files(username: str) -> list:
    """Get files shared with user"""
    shares = load_json(SHARES_FILE)
    shared = []
    
    for share_id, share_data in shares.items():
        if share_data["to"] == username:
            expires = datetime.fromisoformat(share_data["expires"])
            if expires > datetime.now():
                shared.append({
                    "file": share_data["file"],
                    "from": share_data["from"],
                    "permission": share_data["permission"],
                    "share_id": share_id,
                    "icon": get_file_icon(share_data["file"])
                })
    
    return shared

def get_shared_by_me(username: str) -> list:
    """Get files shared by user"""
    shares = load_json(SHARES_FILE)
    shared = []
    
    for share_id, share_data in shares.items():
        if share_data["from"] == username:
            expires = datetime.fromisoformat(share_data["expires"])
            if expires > datetime.now():
                shared.append({
                    "file": share_data["file"],
                    "to": share_data["to"],
                    "permission": share_data["permission"],
                    "share_id": share_id,
                    "icon": get_file_icon(share_data["file"])
                })
    
    return shared

def get_storage_usage(username: str) -> dict:
    """Get storage usage"""
    users = load_json(USERS_FILE)
    used = users[username]["storage_used"]
    
    return {
        "used": used,
        "total": STORAGE_QUOTA,
        "percentage": (used / STORAGE_QUOTA) * 100,
        "remaining": STORAGE_QUOTA - used
    }

def search_files(username: str, query: str) -> list:
    """Search files"""
    files = list_files(username)
    return [f for f in files if query.lower() in f['filename'].lower()]

def get_activity_log(username: str, limit: int = 20) -> list:
    """Get user activity log"""
    logs = load_json(ACTIVITY_LOG_FILE)
    user_logs = [
        log for log in logs.values() 
        if log["username"] == username
    ]
    return sorted(
        user_logs, 
        key=lambda x: x["timestamp"], 
        reverse=True
    )[:limit]

# ============== INITIALIZE ==============
init_files()

# Session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"

# ============== MAIN APP ==============

if not st.session_state.logged_in:
    # AUTH PAGE
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<h1 style='text-align: center; color: #667eea;'>☁️ CloudDrive</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #666;'>Secure Cloud Storage for Everyone</p>", unsafe_allow_html=True)
        
        auth_mode = st.radio("", ["Login", "Register"], horizontal=True, label_visibility="collapsed")
        
        st.divider()
        
        if auth_mode == "Register":
            st.subheader("Create Account")
            reg_user = st.text_input("Username", placeholder="Choose a username")
            reg_email = st.text_input("Email", placeholder="your@email.com")
            reg_pass = st.text_input("Password", type="password", placeholder="Min 6 characters")
            reg_pass_confirm = st.text_input("Confirm Password", type="password")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📝 Create Account", use_container_width=True):
                    if not all([reg_user, reg_email, reg_pass]):
                        st.error("❌ All fields required")
                    elif len(reg_pass) < 6:
                        st.error("❌ Password must be 6+ characters")
                    elif reg_pass != reg_pass_confirm:
                        st.error("❌ Passwords don't match")
                    elif register_user(reg_user, reg_email, reg_pass):
                        st.success("✅ Account created! Login now.")
                    else:
                        st.error("❌ Username already exists")
        
        else:
            st.subheader("Welcome Back")
            login_user = st.text_input("Username", placeholder="Enter username")
            login_pass = st.text_input("Password", type="password")
            
            if st.button("🔓 Login", use_container_width=True, type="primary"):
                if not login_user or not login_pass:
                    st.error("❌ Enter username and password")
                elif authenticate_user(login_user, login_pass):
                    st.session_state.logged_in = True
                    st.session_state.username = login_user
                    log_activity(login_user, "LOGIN", "User logged in")
                    st.success("✅ Login successful!")
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials")

else:
    # MAIN APP
    with st.sidebar:
        st.markdown(f"<h3 style='color: white;'>👤 {st.session_state.username}</h3>", unsafe_allow_html=True)
        st.divider()
        
        users = load_json(USERS_FILE)
        storage = get_storage_usage(st.session_state.username)
        
        st.markdown("### 📊 Storage")
        st.progress(storage["percentage"] / 100)
        st.caption(f"{storage['used'] / (1024*1024):.1f}MB / {storage['total'] / (1024*1024*1024):.0f}GB")
        
        st.divider()
        
        st.markdown("### 📌 Menu")
        page = st.radio(
            "Navigation",
            ["📁 My Files", "📤 Upload", "🔗 Shared with Me", "👥 Shared by Me", 
             "🗑️ Recycle Bin", "📋 Activity Log", "⚙️ Settings"],
            label_visibility="collapsed"
        )
        
        st.divider()
        
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()
    
    # PAGE CONTENT
    if page == "📁 My Files":
        st.title("📁 My Files")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Files", len(list_files(st.session_state.username)))
        with col2:
            st.metric("Storage Used", f"{storage['used'] / (1024*1024):.1f}MB")
        with col3:
            st.metric("Storage Free", f"{storage['remaining'] / (1024*1024):.0f}MB")
        
        st.divider()
        
        col1, col2 = st.columns([3, 1])
        with col1:
            search_query = st.text_input("🔍 Search files...", placeholder="Type filename")
        with col2:
            sort_by = st.selectbox("Sort by", ["Modified (New)", "Modified (Old)", "Name A-Z", "Size"])
        
        files = search_files(st.session_state.username, search_query) if search_query else list_files(st.session_state.username)
        
        if sort_by == "Name A-Z":
            files = sorted(files, key=lambda x: x['filename'])
        elif sort_by == "Size":
            files = sorted(files, key=lambda x: x['size'], reverse=True)
        
        if not files:
            st.info("📭 No files yet. Upload one to get started!")
        else:
            for file in files:
                with st.container(border=True):
                    col1, col2, col3, col4, col5, col6 = st.columns([4, 1, 1, 1, 1, 1])
                    
                    with col1:
                        st.markdown(f"**{file['icon']} {file['filename']}**")
                        st.caption(f"v{file['version']} | {file['size'] / 1024:.1f}KB | {file['modified'][:10]}")
                    
                    with col2:
                        if st.button("⬇️", key=f"dl_{file['filename']}", help="Download"):
                            data = download_file(st.session_state.username, file['filename'])
                            st.download_button(
                                "Download", data, file['filename'],
                                key=f"save_{file['filename']}"
                            )
                    
                    with col3:
                        if st.button("📋", key=f"ver_{file['filename']}", help="Versions"):
                            st.session_state[f"show_v_{file['filename']}"] = not st.session_state.get(f"show_v_{file['filename']}", False)
                    
                    with col4:
                        if st.button("🔗", key=f"share_{file['filename']}", help="Share"):
                            st.session_state[f"show_share_{file['filename']}"] = True
                    
                    with col5:
                        if st.button("⭐", key=f"star_{file['filename']}", help="Favorite"):
                            st.success("Added to favorites!")
                    
                    with col6:
                        if st.button("🗑️", key=f"del_{file['filename']}", help="Delete"):
                            delete_file(st.session_state.username, file['filename'])
                            st.success("Moved to recycle bin")
                            st.rerun()
                    
                    # Versions
                    if st.session_state.get(f"show_v_{file['filename']}", False):
                        st.divider()
                        st.write("**📦 Versions:**")
                        versions = get_file_versions(st.session_state.username, file['filename'])
                        for v in versions:
                            vc1, vc2 = st.columns([3, 1])
                            with vc1:
                                st.caption(f"v{v['version']} | {v['size']/1024:.1f}KB | {v['modified'][:10]}")
                            with vc2:
                                if st.button("Restore", key=f"restore_{file['filename']}_v{v['version']}"):
                                    data = download_file(st.session_state.username, file['filename'], int(v['version']))
                                    upload_file(st.session_state.username, data, file['filename'])
                                    st.rerun()
                    
                    # Share
                    if st.session_state.get(f"show_share_{file['filename']}", False):
                        st.divider()
                        st.write("**🔗 Share with:**")
                        share_user = st.text_input("Username", key=f"share_user_{file['filename']}")
                        share_perm = st.selectbox("Permission", ["view", "download"], key=f"perm_{file['filename']}")
                        if st.button("Share", key=f"share_btn_{file['filename']}"):
                            share_file(st.session_state.username, file['filename'], share_user, share_perm)
                            st.success(f"✅ Shared with {share_user}!")
                            st.session_state[f"show_share_{file['filename']}"] = False
    
    elif page == "📤 Upload":
        st.title("📤 Upload Files")
        
        st.info(f"💾 Available storage: {storage['remaining'] / (1024*1024*1024):.2f}GB")
        
        uploaded_files = st.file_uploader("Choose files", accept_multiple_files=True)
        
        if uploaded_files:
            if st.button("Upload All", type="primary", use_container_width=True):
                for uploaded_file in uploaded_files:
                    upload_file(st.session_state.username, uploaded_file.getvalue(), uploaded_file.name)
                    st.success(f"✅ {uploaded_file.name}")
                st.rerun()
    
    elif page == "🔗 Shared with Me":
        st.title("🔗 Shared with Me")
        
        shared = get_shared_files(st.session_state.username)
        
        if not shared:
            st.info("📭 No files shared with you")
        else:
            for item in shared:
                with st.container(border=True):
                    col1, col2, col3 = st.columns([4, 1, 1])
                    
                    with col1:
                        st.markdown(f"**{item['icon']} {item['file']}**")
                        st.caption(f"Shared by {item['from']} | Permission: {item['permission']}")
                    
                    with col2:
                        if st.button("⬇️ Download", key=f"shared_dl_{item['share_id']}"):
                            data = download_file(item['from'], item['file'])
                            st.download_button("Download", data, item['file'], key=f"shared_save_{item['share_id']}")
                    
                    with col3:
                        if st.button("❌ Remove", key=f"remove_{item['share_id']}"):
                            restore_from_trash(st.session_state.username, item['share_id'])
                            st.rerun()
    
    elif page == "👥 Shared by Me":
        st.title("👥 Shared by Me")
        
        shared_by_me = get_shared_by_me(st.session_state.username)
        
        if not shared_by_me:
            st.info("📭 You haven't shared any files")
        else:
            for item in shared_by_me:
                with st.container(border=True):
                    col1, col2 = st.columns([4, 1])
                    
                    with col1:
                        st.markdown(f"**{item['icon']} {item['file']}**")
                        st.caption(f"Shared with {item['to']} | Permission: {item['permission']}")
                    
                    with col2:
                        if st.button("🔐 Revoke", key=f"revoke_{item['share_id']}"):
                            st.success("Access revoked!")
    
    elif page == "🗑️ Recycle Bin":
        st.title("🗑️ Recycle Bin")
        
        trash = load_json(RECYCLE_BIN_FILE)
        user_trash = [t for t in trash.values() if t["username"] == st.session_state.username]
        
        if not user_trash:
            st.info("🗑️ Recycle bin is empty")
        else:
            for item in user_trash:
                with st.container(border=True):
                    col1, col2, col3 = st.columns([4, 1, 1])
                    
                    with col1:
                        st.markdown(f"**{get_file_icon(item['filename'])} {item['filename']}**")
                        st.caption(f"Deleted: {item['deleted_at'][:10]} | Expires: {item['expires_at'][:10]}")
                    
                    with col2:
                        if st.button("♻️ Restore", key=f"restore_trash_{item['filename']}"):
                            st.success("File restored!")
                    
                    with col3:
                        if st.button("🔴 Delete Permanently", key=f"perm_del_{item['filename']}"):
                            permanently_delete_file(st.session_state.username, item['filename'])
                            st.rerun()
    
    elif page == "📋 Activity Log":
        st.title("📋 Activity Log")
        
        logs = get_activity_log(st.session_state.username, 50)
        
        if not logs:
            st.info("No activity yet")
        else:
            df = pd.DataFrame([
                {
                    "Time": log["timestamp"][:16],
                    "Action": log["action"],
                    "Details": log["details"]
                }
                for log in logs
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    elif page == "⚙️ Settings":
        st.title("⚙️ Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Account")
            users = load_json(USERS_FILE)
            user = users[st.session_state.username]
            
            st.write(f"**Username:** {st.session_state.username}")
            st.write(f"**Email:** {user['email']}")
            st.write(f"**Plan:** {user['plan'].capitalize()}")
            st.write(f"**Member since:** {user['created'][:10]}")
            
            if st.button("🔐 Change Password"):
                st.info("Password change feature - coming soon!")
            
            if st.button("🆙 Upgrade Plan"):
                st.info("Premium plans - coming soon!")
        
        with col2:
            st.subheader("Preferences")
            
            theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
            notifications = st.checkbox("Enable Notifications", value=True)
            two_factor = st.checkbox("Two-Factor Authentication")
            
            if st.button("💾 Save Settings"):
                st.success("✅ Settings saved!")
