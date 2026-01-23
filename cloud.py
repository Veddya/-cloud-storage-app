import streamlit as st
import os
import json
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import mimetypes
from io import BytesIO
import pandas as pd
from collections import defaultdict

# ============== PAGE CONFIG ==============
st.set_page_config(
    page_title="CloudDrive Pro - Enterprise Cloud Storage",
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
    .success-box {
        background-color: #d4edda;
        padding: 12px;
        border-radius: 6px;
        border: 1px solid #c3e6cb;
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
FOLDERS_FILE = STORAGE_DIR / "folders.json"
COMMENTS_FILE = STORAGE_DIR / "comments.json"
TAGS_FILE = STORAGE_DIR / "tags.json"
ANALYTICS_FILE = STORAGE_DIR / "analytics.json"
TEAMS_FILE = STORAGE_DIR / "teams.json"
NOTIFICATIONS_FILE = STORAGE_DIR / "notifications.json"

STORAGE_QUOTA = 5 * 1024 * 1024 * 1024  # 5GB per user

for dir_path in [STORAGE_DIR, METADATA_DIR]:
    dir_path.mkdir(exist_ok=True)

# ============== UTILITY FUNCTIONS ==============

def init_files():
    """Initialize storage files"""
    for file_path in [USERS_FILE, SHARES_FILE, RECYCLE_BIN_FILE, ACTIVITY_LOG_FILE, 
                      FOLDERS_FILE, COMMENTS_FILE, TAGS_FILE, ANALYTICS_FILE, TEAMS_FILE, NOTIFICATIONS_FILE]:
        if not file_path.exists():
            file_path.write_text(json.dumps({}))

def load_json(file_path: Path) -> dict:
    """Load JSON file"""
    try:
        return json.loads(file_path.read_text())
    except:
        return {}

def save_json(file_path: Path, data: dict):
    """Save JSON file"""
    file_path.write_text(json.dumps(data, indent=2))

def is_valid_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def send_verification_email(email: str, username: str) -> str:
    """Simulate email verification"""
    verification_code = secrets.token_hex(3).upper()
    # In production, use smtp/SendGrid
    return verification_code

def send_notification_email(email: str, subject: str, message: str):
    """Send email notification"""
    # In production, use smtp/SendGrid
    pass

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

def add_notification(username: str, notification_type: str, title: str, message: str):
    """Add notification"""
    notifs = load_json(NOTIFICATIONS_FILE)
    notif_id = str(uuid.uuid4())
    notifs[notif_id] = {
        "username": username,
        "type": notification_type,
        "title": title,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "read": False
    }
    save_json(NOTIFICATIONS_FILE, notifs)

def record_analytics(username: str, metric: str, value: any):
    """Record analytics"""
    analytics = load_json(ANALYTICS_FILE)
    if username not in analytics:
        analytics[username] = {}
    analytics[username][metric] = {
        "value": value,
        "timestamp": datetime.now().isoformat()
    }
    save_json(ANALYTICS_FILE, analytics)

def register_user(username: str, email: str, password: str) -> tuple:
    """Register new user"""
    users = load_json(USERS_FILE)
    
    if username in users:
        return False, "Username already exists"
    
    if not is_valid_email(email):
        return False, "Invalid email format"
    
    if len(password) < 6:
        return False, "Password must be 6+ characters"
    
    # Send verification email
    verification_code = send_verification_email(email, username)
    
    users[username] = {
        "email": email,
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "created": datetime.now().isoformat(),
        "storage_used": 0,
        "plan": "free",
        "verified": False,
        "verification_code": verification_code,
        "profile_pic": None,
        "bio": "",
        "settings": {
            "theme": "light",
            "notifications": True,
            "two_factor": False,
            "email_shares": True,
            "email_comments": True
        },
        "favorites": [],
        "tags": {}
    }
    
    save_json(USERS_FILE, users)
    log_activity(username, "REGISTER", "New account created")
    record_analytics(username, "account_created", 1)
    
    return True, verification_code

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user"""
    users = load_json(USERS_FILE)
    if username not in users:
        return False
    return users[username]["password"] == hashlib.sha256(password.encode()).hexdigest()

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

def create_folder(username: str, folder_name: str, parent_id: str = "root") -> str:
    """Create folder"""
    folders = load_json(FOLDERS_FILE)
    folder_id = str(uuid.uuid4())
    
    folders[folder_id] = {
        "username": username,
        "name": folder_name,
        "parent_id": parent_id,
        "created": datetime.now().isoformat(),
        "color": "#667eea"
    }
    
    save_json(FOLDERS_FILE, folders)
    log_activity(username, "CREATE_FOLDER", f"Created folder: {folder_name}")
    return folder_id

def get_user_folders(username: str) -> list:
    """Get user folders"""
    folders = load_json(FOLDERS_FILE)
    user_folders = [f for f in folders.values() if f["username"] == username]
    return sorted(user_folders, key=lambda x: x["created"], reverse=True)

def upload_file(username: str, file_data, filename: str, folder_id: str = "root"):
    """Upload file with versioning"""
    user_path = get_user_storage_path(username)
    
    versions = get_file_versions(username, filename)
    next_version = 1 if not versions else int(versions[0]["version"]) + 1
    
    versioned_name = f"{filename}.v{next_version}"
    file_path = user_path / versioned_name
    
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    users = load_json(USERS_FILE)
    users[username]["storage_used"] = sum(
        f.stat().st_size for f in user_path.glob("*") if f.is_file()
    )
    save_json(USERS_FILE, users)
    
    log_activity(username, "UPLOAD", f"Uploaded {filename}")
    record_analytics(username, "files_uploaded", len(list_files(username)))
    add_notification(username, "upload", "File Uploaded", f"{filename} uploaded successfully")
    
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
    users = load_json(USERS_FILE)
    user_data = users.get(username, {})
    favorites = user_data.get("favorites", [])
    
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
                "icon": get_file_icon(base_name),
                "is_favorite": base_name in favorites
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
    add_notification(username, "delete", "File Deleted", f"{filename} moved to trash")

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

def toggle_favorite(username: str, filename: str):
    """Toggle favorite status"""
    users = load_json(USERS_FILE)
    if filename in users[username]["favorites"]:
        users[username]["favorites"].remove(filename)
    else:
        users[username]["favorites"].append(filename)
    save_json(USERS_FILE, users)

def add_tag(username: str, filename: str, tag: str):
    """Add tag to file"""
    tags = load_json(TAGS_FILE)
    tag_id = str(uuid.uuid4())
    
    tags[tag_id] = {
        "username": username,
        "filename": filename,
        "tag": tag,
        "created": datetime.now().isoformat()
    }
    save_json(TAGS_FILE, tags)

def get_tags(username: str, filename: str) -> list:
    """Get file tags"""
    tags = load_json(TAGS_FILE)
    file_tags = [t["tag"] for t in tags.values() 
                 if t["username"] == username and t["filename"] == filename]
    return file_tags

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
    
    users = load_json(USERS_FILE)
    if share_with in users:
        add_notification(share_with, "share", "File Shared", f"{username} shared {filename} with you")
        if users[share_with]["settings"].get("email_shares"):
            send_notification_email(users[share_with]["email"], "File Shared", 
                                   f"{username} shared {filename} with you")
    
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

def add_comment(username: str, filename: str, comment: str):
    """Add comment to file"""
    comments = load_json(COMMENTS_FILE)
    comment_id = str(uuid.uuid4())
    
    comments[comment_id] = {
        "username": username,
        "filename": filename,
        "comment": comment,
        "created": datetime.now().isoformat(),
        "replies": []
    }
    
    save_json(COMMENTS_FILE, comments)
    log_activity(username, "COMMENT", f"Commented on {filename}")

def get_comments(filename: str) -> list:
    """Get file comments"""
    comments = load_json(COMMENTS_FILE)
    file_comments = [c for c in comments.values() if c["filename"] == filename]
    return sorted(file_comments, key=lambda x: x["created"], reverse=True)

def create_team(username: str, team_name: str, description: str = "") -> str:
    """Create team"""
    teams = load_json(TEAMS_FILE)
    team_id = str(uuid.uuid4())
    
    teams[team_id] = {
        "owner": username,
        "name": team_name,
        "description": description,
        "created": datetime.now().isoformat(),
        "members": [username],
        "storage_used": 0
    }
    
    save_json(TEAMS_FILE, teams)
    log_activity(username, "CREATE_TEAM", f"Created team: {team_name}")
    return team_id

def get_user_teams(username: str) -> list:
    """Get user teams"""
    teams = load_json(TEAMS_FILE)
    user_teams = [t for t in teams.values() if username in t["members"]]
    return user_teams

def add_team_member(team_id: str, member_username: str):
    """Add member to team"""
    teams = load_json(TEAMS_FILE)
    if team_id in teams:
        teams[team_id]["members"].append(member_username)
        save_json(TEAMS_FILE, teams)
        return True
    return False

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

def get_activity_log(username: str, limit: int = 50) -> list:
    """Get user activity log"""
    logs = load_json(ACTIVITY_LOG_FILE)
    user_logs = [log for log in logs.values() if log["username"] == username]
    return sorted(user_logs, key=lambda x: x["timestamp"], reverse=True)[:limit]

def get_notifications(username: str) -> list:
    """Get user notifications"""
    notifs = load_json(NOTIFICATIONS_FILE)
    user_notifs = [n for n in notifs.values() if n["username"] == username]
    return sorted(user_notifs, key=lambda x: x["timestamp"], reverse=True)

def get_analytics_dashboard(username: str) -> dict:
    """Get analytics for user"""
    analytics = load_json(ANALYTICS_FILE)
    files = list_files(username)
    logs = get_activity_log(username, 100)
    
    # Calculate metrics
    file_types = defaultdict(int)
    for file in files:
        ext = Path(file["filename"]).suffix or "unknown"
        file_types[ext] += 1
    
    actions = defaultdict(int)
    for log in logs:
        actions[log["action"]] += 1
    
    return {
        "total_files": len(files),
        "total_storage": get_storage_usage(username),
        "file_types": dict(file_types),
        "recent_actions": dict(actions),
        "total_shared": len(get_shared_by_me(username))
    }

# ============== INITIALIZE ==============
init_files()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"

# ============== MAIN APP ==============

if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<h1 style='text-align: center; color: #667eea;'>☁️ CloudDrive Pro</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #666;'>Enterprise Cloud Storage Solution</p>", unsafe_allow_html=True)
        
        auth_mode = st.radio("", ["Login", "Register"], horizontal=True, label_visibility="collapsed")
        st.divider()
        
        if auth_mode == "Register":
            st.subheader("Create Your Account")
            reg_user = st.text_input("Username", placeholder="Choose a username")
            reg_email = st.text_input("Email", placeholder="your@email.com")
            reg_pass = st.text_input("Password", type="password", placeholder="Min 6 characters")
            reg_pass_confirm = st.text_input("Confirm Password", type="password")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📝 Create Account", use_container_width=True, type="primary"):
                    success, message = register_user(reg_user, reg_email, reg_pass)
                    if success:
                        st.success(f"✅ Account created! Verification code: {message}")
                        st.info("Check your email for verification link")
                    else:
                        st.error(f"❌ {message}")
        
        else:
            st.subheader("Welcome Back")
            login_user = st.text_input("Username", placeholder="Enter username")
            login_pass = st.text_input("Password", type="password")
            
            if st.button("🔓 Login", use_container_width=True, type="primary"):
                if authenticate_user(login_user, login_pass):
                    st.session_state.logged_in = True
                    st.session_state.username = login_user
                    log_activity(login_user, "LOGIN", "User logged in")
                    st.success("✅ Login successful!")
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials")

else:
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
            ["📁 My Files", "📂 Folders", "📤 Upload", "🔗 Shared with Me", 
             "👥 Shared by Me", "👫 Teams", "🗑️ Recycle Bin", "📊 Analytics", 
             "🔔 Notifications", "📋 Activity Log", "⚙️ Settings"],
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
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Files", len(list_files(st.session_state.username)))
        with col2:
            st.metric("Storage Used", f"{storage['used'] / (1024*1024):.1f}MB")
        with col3:
            st.metric("Storage Free", f"{storage['remaining'] / (1024*1024*1024):.2f}GB")
        with col4:
            st.metric("Shared", len(get_shared_by_me(st.session_state.username)))
        
        st.divider()
        
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            search_query = st.text_input("🔍 Search files...", placeholder="Type filename")
        with col2:
            sort_by = st.selectbox("Sort", ["Modified (New)", "Modified (Old)", "Name A-Z", "Size"])
        with col3:
            view_mode = st.selectbox("View", ["List", "Grid"])
        
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
                    col1, col2, col3, col4, col5, col6, col7, col8 = st.columns([4, 1, 1, 1, 1, 1, 1, 1])
                    
                    with col1:
                        st.markdown(f"**{file['icon']} {file['filename']}**")
                        tags = get_tags(st.session_state.username, file['filename'])
                        if tags:
                            st.caption(f"Tags: {', '.join(tags)}")
                        st.caption(f"v{file['version']} | {file['size'] / 1024:.1f}KB | {file['modified'][:10]}")
                    
                    with col2:
                        if st.button("⬇️", key=f"dl_{file['filename']}", help="Download"):
                            data = download_file(st.session_state.username, file['filename'])
                            st.download_button("Download", data, file['filename'], key=f"save_{file['filename']}")
                    
                    with col3:
                        if st.button("📋", key=f"ver_{file['filename']}", help="Versions"):
                            st.session_state[f"show_v_{file['filename']}"] = not st.session_state.get(f"show_v_{file['filename']}", False)
                    
                    with col4:
                        if st.button("🔗", key=f"share_{file['filename']}", help="Share"):
                            st.session_state[f"show_share_{file['filename']}"] = True
                    
                    with col5:
                        fav_icon = "⭐" if file['is_favorite'] else "☆"
                        if st.button(fav_icon, key=f"star_{file['filename']}", help="Favorite"):
                            toggle_favorite(st.session_state.username, file['filename'])
                            st.rerun()
                    
                    with col6:
                        if st.button("💬", key=f"comment_{file['filename']}", help="Comments"):
                            st.session_state[f"show_comment_{file['filename']}"] = True
                    
                    with col7:
                        if st.button("🏷️", key=f"tag_{file['filename']}", help="Tags"):
                            st.session_state[f"show_tag_{file['filename']}"] = True
                    
                    with col8:
                        if st.button("🗑️", key=f"del_{file['filename']}", help="Delete"):
                            delete_file(st.session_state.username, file['filename'])
                            st.success("Moved to recycle bin")
                            st.rerun()
                    
                    # Versions
                    if st.session_state.get(f"show_v_{file['filename']}", False):
                        st.divider()
                        st.write("**📦 Versions:**")
                        versions = get_file_versions(st.session_state.
