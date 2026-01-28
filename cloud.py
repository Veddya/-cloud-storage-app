"""
CloudDrive Pro - Enterprise Cloud Storage Application
Complete application with all imports and dependencies
"""

# ============== IMPORTS & LIBRARIES ==============
import streamlit as st
import json
import hashlib
import re
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import pandas as pd
from collections import defaultdict
import mimetypes

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
</style>
""", unsafe_allow_html=True)

# ============== FILE PATHS CONFIGURATION ==============
STORAGE_DIR = Path("cloud_storage")
STORAGE_DIR.mkdir(exist_ok=True)

USERS_FILE = STORAGE_DIR / "users.json"
SHARES_FILE = STORAGE_DIR / "shares.json"
RECYCLE_BIN_FILE = STORAGE_DIR / "recycle_bin.json"
ACTIVITY_LOG_FILE = STORAGE_DIR / "activity_log.json"
FOLDERS_FILE = STORAGE_DIR / "folders.json"
COMMENTS_FILE = STORAGE_DIR / "comments.json"
TAGS_FILE = STORAGE_DIR / "tags.json"
TEAMS_FILE = STORAGE_DIR / "teams.json"
NOTIFICATIONS_FILE = STORAGE_DIR / "notifications.json"
SESSION_FILE = STORAGE_DIR / "sessions.json"

STORAGE_QUOTA = 5 * 1024 * 1024 * 1024  # 5GB per user

# ============== UTILITY FUNCTIONS ==============

def init_files():
    """Initialize all JSON storage files"""
    files_to_init = [
        USERS_FILE, SHARES_FILE, RECYCLE_BIN_FILE, ACTIVITY_LOG_FILE,
        FOLDERS_FILE, COMMENTS_FILE, TAGS_FILE, TEAMS_FILE,
        NOTIFICATIONS_FILE, SESSION_FILE
    ]
    for f in files_to_init:
        if not f.exists():
            f.write_text(json.dumps({}))

def load_json(path):
    """Load JSON file safely"""
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except:
        return {}

def save_json(path, data):
    """Save JSON file safely"""
    try:
        path.write_text(json.dumps(data, indent=2))
    except:
        pass

def is_valid_email(email):
    """Validate email format"""
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def save_session(username, remember_me=False):
    """Save session for persistent login"""
    try:
        sessions = load_json(SESSION_FILE)
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "username": username,
            "created": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=30 if remember_me else 1)).isoformat(),
            "remember_me": remember_me
        }
        save_json(SESSION_FILE, sessions)
        return session_id
    except:
        return None

def load_session(session_id):
    """Load session if still valid"""
    try:
        sessions = load_json(SESSION_FILE)
        if session_id not in sessions:
            return None
        
        session = sessions[session_id]
        expires = datetime.fromisoformat(session.get("expires", datetime.now().isoformat()))
        
        if expires < datetime.now():
            del sessions[session_id]
            save_json(SESSION_FILE, sessions)
            return None
        
        return session.get("username")
    except:
        return None

def get_remember_me_session():
    """Get remembered session from browser"""
    try:
        sessions = load_json(SESSION_FILE)
        for session_id, session in sessions.items():
            if session.get("remember_me"):
                expires = datetime.fromisoformat(session.get("expires", datetime.now().isoformat()))
                if expires > datetime.now():
                    return session.get("username")
        return None
    except:
        return None

def log_activity(username, action, details):
    """Log user activity"""
    try:
        logs = load_json(ACTIVITY_LOG_FILE)
        logs[str(uuid.uuid4())] = {
            "username": username,
            "action": action,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        save_json(ACTIVITY_LOG_FILE, logs)
    except:
        pass

def add_notification(username, notif_type, title, message):
    """Add notification"""
    try:
        notifs = load_json(NOTIFICATIONS_FILE)
        notifs[str(uuid.uuid4())] = {
            "username": username,
            "type": notif_type,
            "title": title,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "read": False
        }
        save_json(NOTIFICATIONS_FILE, notifs)
    except:
        pass

def register_user(username, email, password):
    """Register new user"""
    try:
        users = load_json(USERS_FILE)
        if username in users:
            return False, "Username exists"
        if not is_valid_email(email):
            return False, "Invalid email"
        if len(password) < 6:
            return False, "Password 6+ chars"
        
        users[username] = {
            "email": email,
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "created": datetime.now().isoformat(),
            "storage_used": 0,
            "plan": "free",
            "settings": {"theme": "light", "notifications": True},
            "favorites": []
        }
        save_json(USERS_FILE, users)
        log_activity(username, "REGISTER", "Account created")
        return True, "Success"
    except:
        return False, "Registration error"

def authenticate_user(username, password):
    """Authenticate user"""
    try:
        users = load_json(USERS_FILE)
        if username not in users:
            return False
        return users[username]["password"] == hashlib.sha256(password.encode()).hexdigest()
    except:
        return False

def get_user_storage_path(username):
    """Get user storage path"""
    try:
        path = STORAGE_DIR / username
        path.mkdir(exist_ok=True)
        return path
    except:
        return STORAGE_DIR

def get_file_icon(filename):
    """Get file type icon"""
    ext = Path(filename).suffix.lower()
    icons = {
        '.pdf': '📄', '.doc': '📝', '.docx': '📝', '.xls': '📊', '.xlsx': '📊',
        '.ppt': '📑', '.pptx': '📑', '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️',
        '.gif': '🖼️', '.mp4': '🎥', '.avi': '🎥', '.mp3': '🎵', '.wav': '🎵',
        '.zip': '📦', '.rar': '📦', '.txt': '📄', '.csv': '📊'
    }
    return icons.get(ext, '📁')

def create_folder(username, folder_name):
    """Create folder"""
    try:
        folders = load_json(FOLDERS_FILE)
        folder_id = str(uuid.uuid4())
        folders[folder_id] = {
            "username": username,
            "name": folder_name,
            "created": datetime.now().isoformat()
        }
        save_json(FOLDERS_FILE, folders)
        log_activity(username, "CREATE_FOLDER", f"Created {folder_name}")
        return folder_id
    except:
        return None

def get_user_folders(username):
    """Get user folders"""
    try:
        folders = load_json(FOLDERS_FILE)
        return [f for f in folders.values() if f.get("username") == username]
    except:
        return []

def upload_file(username, file_data, filename):
    """Upload file with versioning"""
    try:
        user_path = get_user_storage_path(username)
        user_path.mkdir(parents=True, exist_ok=True)
        
        next_version = 1
        for file in user_path.iterdir():
            if file.is_file() and filename in file.name and '.v' in file.name:
                try:
                    ver = int(file.name.rsplit('.v', 1)[1])
                    next_version = max(next_version, ver + 1)
                except:
                    pass
        
        versioned_filename = f"{filename}.v{next_version}"
        file_path = user_path / versioned_filename
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        if not file_path.exists() or file_path.stat().st_size == 0:
            if file_path.exists():
                file_path.unlink()
            return None
        
        users = load_json(USERS_FILE)
        if username in users:
            total_size = sum(f.stat().st_size for f in user_path.iterdir() if f.is_file())
            users[username]["storage_used"] = total_size
            save_json(USERS_FILE, users)
        
        log_activity(username, "UPLOAD", f"Uploaded {filename}")
        add_notification(username, "upload", "Upload", f"{filename} uploaded (v{next_version})")
        
        return next_version
    except:
        return None

def get_file_versions(username, filename):
    """Get all file versions"""
    try:
        user_path = get_user_storage_path(username)
        versions = []
        
        if not user_path.exists():
            return []
        
        for file in user_path.iterdir():
            if file.is_file() and filename in file.name and '.v' in file.name:
                try:
                    version_num = file.name.rsplit('.v', 1)[1]
                    versions.append({
                        "version": version_num,
                        "path": file,
                        "size": file.stat().st_size,
                        "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
                    })
                except:
                    pass
        
        return sorted(versions, key=lambda x: int(x["version"]), reverse=True)
    except:
        return []

def list_files(username):
    """List latest file versions"""
    try:
        user_path = get_user_storage_path(username)
        files = {}
        users = load_json(USERS_FILE)
        favorites = users.get(username, {}).get("favorites", [])
        
        if not user_path.exists():
            return []
        
        for file in user_path.iterdir():
            if not file.is_file():
                continue
            
            filename = file.name
            
            if '.v' in filename:
                parts = filename.rsplit('.v', 1)
                if len(parts) == 2:
                    base_name, version_str = parts
                    try:
                        version = int(version_str)
                        
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
                    except ValueError:
                        pass
        
        return sorted(files.values(), key=lambda x: x["modified"], reverse=True)
    except:
        return []

def download_file(username, filename, version=None):
    """Download file"""
    try:
        user_path = get_user_storage_path(username)
        
        if version:
            file_path = user_path / f"{filename}.v{version}"
        else:
            versions = get_file_versions(username, filename)
            if not versions:
                return None
            file_path = versions[0]["path"]
        
        return file_path.read_bytes() if file_path.exists() else None
    except:
        return None

def delete_file(username, filename):
    """Move to recycle bin"""
    try:
        trash = load_json(RECYCLE_BIN_FILE)
        trash[str(uuid.uuid4())] = {
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
    except:
        pass

def permanently_delete_file(username, filename):
    """Permanently delete file"""
    try:
        user_path = get_user_storage_path(username)
        for file in user_path.glob(f"{filename}.v*"):
            file.unlink()
    except:
        pass

def toggle_favorite(username, filename):
    """Toggle favorite status"""
    try:
        users = load_json(USERS_FILE)
        if username in users:
            if filename in users[username]["favorites"]:
                users[username]["favorites"].remove(filename)
            else:
                users[username]["favorites"].append(filename)
            save_json(USERS_FILE, users)
    except:
        pass

def add_tag(username, filename, tag):
    """Add tag to file"""
    try:
        tags = load_json(TAGS_FILE)
        tags[str(uuid.uuid4())] = {
            "username": username,
            "filename": filename,
            "tag": tag,
            "created": datetime.now().isoformat()
        }
        save_json(TAGS_FILE, tags)
    except:
        pass

def get_tags(username, filename):
    """Get file tags"""
    try:
        tags = load_json(TAGS_FILE)
        return [t["tag"] for t in tags.values() if t.get("username") == username and t.get("filename") == filename]
    except:
        return []

def share_file(username, filename, share_with, permission="view"):
    """Share file"""
    try:
        shares = load_json(SHARES_FILE)
        share_id = str(uuid.uuid4())
        shares[share_id] = {
            "from": username,
            "to": share_with,
            "file": filename,
            "permission": permission,
            "created": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=30)).isoformat()
        }
        save_json(SHARES_FILE, shares)
        log_activity(username, "SHARE", f"Shared {filename} with {share_with}")
        add_notification(share_with, "share", "Shared", f"{username} shared {filename}")
        return share_id
    except:
        return None

def get_shared_files(username):
    """Get files shared with user"""
    try:
        shares = load_json(SHARES_FILE)
        shared = []
        
        for share_id, share_data in shares.items():
            if share_data.get("to") == username:
                expires = datetime.fromisoformat(share_data.get("expires", datetime.now().isoformat()))
                if expires > datetime.now():
                    shared.append({
                        "file": share_data["file"],
                        "from": share_data["from"],
                        "permission": share_data["permission"],
                        "share_id": share_id,
                        "icon": get_file_icon(share_data["file"])
                    })
        
        return shared
    except:
        return []

def get_shared_by_me(username):
    """Get files shared by user"""
    try:
        shares = load_json(SHARES_FILE)
        shared = []
        
        for share_id, share_data in shares.items():
            if share_data.get("from") == username:
                expires = datetime.fromisoformat(share_data.get("expires", datetime.now().isoformat()))
                if expires > datetime.now():
                    shared.append({
                        "file": share_data["file"],
                        "to": share_data["to"],
                        "permission": share_data["permission"],
                        "share_id": share_id,
                        "icon": get_file_icon(share_data["file"])
                    })
        
        return shared
    except:
        return []

def add_comment(username, filename, comment):
    """Add comment to file"""
    try:
        comments = load_json(COMMENTS_FILE)
        comments[str(uuid.uuid4())] = {
            "username": username,
            "filename": filename,
            "comment": comment,
            "created": datetime.now().isoformat()
        }
        save_json(COMMENTS_FILE, comments)
    except:
        pass

def get_comments(filename):
    """Get file comments"""
    try:
        comments = load_json(COMMENTS_FILE)
        file_comments = [c for c in comments.values() if c.get("filename") == filename]
        return sorted(file_comments, key=lambda x: x.get("created", ""), reverse=True)
    except:
        return []

def create_team(username, team_name, description=""):
    """Create team"""
    try:
        teams = load_json(TEAMS_FILE)
        team_id = str(uuid.uuid4())
        teams[team_id] = {
            "owner": username,
            "name": team_name,
            "description": description,
            "created": datetime.now().isoformat(),
            "members": [username]
        }
        save_json(TEAMS_FILE, teams)
        log_activity(username, "CREATE_TEAM", f"Created {team_name}")
        return team_id
    except:
        return None

def get_user_teams(username):
    """Get user teams"""
    try:
        teams = load_json(TEAMS_FILE)
        return [t for t in teams.values() if username in t.get("members", [])]
    except:
        return []

def get_storage_usage(username):
    """Get storage usage"""
    try:
        users = load_json(USERS_FILE)
        used = users.get(username, {}).get("storage_used", 0)
        return {
            "used": used,
            "total": STORAGE_QUOTA,
            "percentage": (used / STORAGE_QUOTA) * 100 if STORAGE_QUOTA > 0 else 0,
            "remaining": STORAGE_QUOTA - used
        }
    except:
        return {"used": 0, "total": STORAGE_QUOTA, "percentage": 0, "remaining": STORAGE_QUOTA}

def search_files(username, query):
    """Search files"""
    try:
        files = list_files(username)
        return [f for f in files if query.lower() in f['filename'].lower()]
    except:
        return []

def get_activity_log(username, limit=50):
    """Get user activity log"""
    try:
        logs = load_json(ACTIVITY_LOG_FILE)
        user_logs = [log for log in logs.values() if log.get("username") == username]
        return sorted(user_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
    except:
        return []

def get_notifications(username):
    """Get user notifications"""
    try:
        notifs = load_json(NOTIFICATIONS_FILE)
        user_notifs = [n for n in notifs.values() if n.get("username") == username]
        return sorted(user_notifs, key=lambda x: x.get("timestamp", ""), reverse=True)
    except:
        return []

def get_analytics(username):
    """Get analytics for user"""
    try:
        files = list_files(username)
        logs = get_activity_log(username, 100)
        
        file_types = defaultdict(int)
        for file in files:
            ext = Path(file.get("filename", "")).suffix or "unknown"
            file_types[ext] += 1
        
        actions = defaultdict(int)
        for log in logs:
            actions[log.get("action", "OTHER")] += 1
        
        return {
            "total_files": len(files),
            "storage": get_storage_usage(username),
            "file_types": dict(file_types),
            "actions": dict(actions),
            "shared": len(get_shared_by_me(username))
        }
    except:
        return {
            "total_files": 0,
            "storage": get_storage_usage(username),
            "file_types": {},
            "actions": {},
            "shared": 0
        }

# ============== INITIALIZE APP ==============
init_files()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "session_id" not in st.session_state:
    st.session_state.session_id = None

# Auto-login from remembered session
if not st.session_state.logged_in:
    remembered_user = get_remember_me_session()
    if remembered_user:
        st.session_state.logged_in = True
        st.session_state.username = remembered_user
        log_activity(remembered_user, "AUTO_LOGIN", "Auto-logged in from remembered session")
        st.rerun()

# Check for shared file from email link
query_params = st.query_params
if "file" in query_params and "from" in query_params:
    shared_file = query_params["file"]
    shared_from = query_params["from"]
    
    st.info(f"📧 **Shared File Preview**\n\nFile: **{shared_file}**\nShared by: **{shared_from}**")
    
    try:
        file_data = download_file(shared_from, shared_file)
        if file_data:
            st.success("✅ File available to download")
            st.download_button(f"⬇️ Download {shared_file}", file_data, shared_file)
        else:
            st.error("❌ File not found or expired")
    except:
        st.error("❌ Unable to access shared file")
    
    st.divider()
    st.write("**Login or Register to access more features**")
    st.stop()

# ============== MAIN APP ==============

if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center; color: #667eea;'>☁️ CloudDrive Pro</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center;'>Enterprise Cloud Storage</p>", unsafe_allow_html=True)
        auth_mode = st.radio("", ["Login", "Register"], horizontal=True, label_visibility="collapsed")
        st.divider()
        
        if auth_mode == "Register":
            st.subheader("Create Account")
            reg_user = st.text_input("Username")
            reg_email = st.text_input("Email")
            reg_pass = st.text_input("Password", type="password")
            if st.button("📝 Register", use_container_width=True, type="primary"):
                success, msg = register_user(reg_user, reg_email, reg_pass)
                if success:
                    st.success("✅ Account created!")
                else:
                    st.error(f"❌ {msg}")
        else:
            st.subheader("Login")
            login_user = st.text_input("Username")
            login_pass = st.text_input("Password", type="password")
            remember_me = st.checkbox("🔐 Keep me signed in for 30 days")
            
            if st.button("🔓 Login", use_container_width=True, type="primary"):
                if authenticate_user(login_user, login_pass):
                    st.session_state.logged_in = True
                    st.session_state.username = login_user
                    
                    if remember_me:
                        session_id = save_session(login_user, remember_me=True)
                        st.session_state.session_id = session_id
                        st.success("✅ You'll be kept signed in for 30 days!")
                    
                    log_activity(login_user, "LOGIN", "Logged in")
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials")

else:
    with st.sidebar:
        st.markdown(f"<h3 style='color: white;'>👤 {st.session_state.username}</h3>", unsafe_allow_html=True)
        st.divider()
        
        storage = get_storage_usage(st.session_state.username)
        
        st.markdown("### 📊 Storage")
        st.progress(min(storage["percentage"] / 100, 1.0))
        st.caption(f"{storage['used'] / (1024*1024):.1f}MB / {storage['total'] / (1024*1024*1024):.0f}GB")
        st.divider()
        
        st.markdown("### 📌 Menu")
        page = st.radio(
            "",
            ["📁 Files", "📂 Folders", "📤 Upload", "🔗 Shared", "👥 Teams", 
             "🗑️ Trash", "📊 Analytics", "🔔 Alerts", "📋 Activity", "⚙️ Settings"],
            label_visibility="collapsed"
        )
        
        st.divider()
        
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = None
            
            if st.session_state.get("session_id"):
                try:
                    sessions = load_json(SESSION_FILE)
                    if st.session_state.session_id in sessions:
                        del sessions[st.session_state.session_id]
                        save_json(SESSION_FILE, sessions)
                except:
                    pass
                st.session_state.session_id = None
            
            log_activity(st.session_state.username or "unknown", "LOGOUT", "Logged out")
            st.rerun()
    
    # ============== PAGES ==============
    
    if page == "📁 Files":
        st.title("📁 My Files")
        try:
            files = list_files(st.session_state.username)
            shared = get_shared_by_me(st.session_state.username)
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Files", len(files))
            with c2:
                st.metric("Used", f"{storage['used'] / (1024*1024):.1f}MB")
            with c3:
                st.metric("Free", f"{storage['remaining'] / (1024*1024*1024):.2f}GB")
            with c4:
                st.metric("Shared", len(shared))
        except:
            st.warning("⚠️ Could not load metrics")
        
        st.divider()
        
        c1, c2, c3 = st.columns([3, 1, 1])
        with c1:
            search = st.text_input("🔍 Search")
        with c2:
            sort = st.selectbox("Sort", ["New", "Old", "Name", "Size"])
        with c3:
            st.selectbox("View", ["List"])
        
        try:
            files = search_files(st.session_state.username, search) if search else list_files(st.session_state.username)
            if sort == "Name":
                files = sorted(files, key=lambda x: x['filename'])
            elif sort == "Size":
                files = sorted(files, key=lambda x: x['size'], reverse=True)
            
            if not files:
                st.info("📭 No files")
            else:
                for file in files:
                    with st.container(border=True):
                        c1, c2, c3, c4, c5, c6, c7, c8 = st.columns([4, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8, 0.8])
                        with c1:
                            st.write(f"**{file['icon']} {file['filename']}**")
                            tags = get_tags(st.session_state.username, file['filename'])
                            if tags:
                                st.caption(f"Tags: {', '.join(tags)}")
                            st.caption(f"v{file['version']} | {file['size']/1024:.1f}KB")
                        
                        with c2:
                            if st.button("⬇️", key=f"dl_{file['filename']}"):
                                data = download_file(st.session_state.username, file['filename'])
                                if data:
                                    st.download_button("", data, file['filename'], key=f"save_{file['filename']}")
                        with c3:
                            if st.button("📋", key=f"ver_{file['filename']}"):
                                st.session_state[f"show_v_{file['filename']}"] = not st.session_state.get(f"show_v_{file['filename']}", False)
                        with c4:
                            if st.button("🔗", key=f"share_{file['filename']}"):
                                st.session_state[f"show_share_{file['filename']}"] = True
                        with c5:
                            fav = "
