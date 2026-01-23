import streamlit as st
import json
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import pandas as pd
from collections import defaultdict

st.set_page_config(page_title="CloudDrive Pro", page_icon="☁️", layout="wide")

st.markdown("""<style>
    [data-testid="stSidebar"] { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
    .main { background-color: #f5f7fa; }
</style>""", unsafe_allow_html=True)

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

STORAGE_QUOTA = 5 * 1024 * 1024 * 1024

def init_files():
    for f in [USERS_FILE, SHARES_FILE, RECYCLE_BIN_FILE, ACTIVITY_LOG_FILE, FOLDERS_FILE, COMMENTS_FILE, TAGS_FILE, TEAMS_FILE, NOTIFICATIONS_FILE]:
        if not f.exists():
            f.write_text(json.dumps({}))

def load_json(path):
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except:
        return {}

def save_json(path, data):
    try:
        path.write_text(json.dumps(data, indent=2))
    except:
        pass

def is_valid_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def log_activity(username, action, details):
    try:
        logs = load_json(ACTIVITY_LOG_FILE)
        logs[str(uuid.uuid4())] = {"username": username, "action": action, "details": details, "timestamp": datetime.now().isoformat()}
        save_json(ACTIVITY_LOG_FILE, logs)
    except:
        pass

def add_notification(username, notif_type, title, message):
    try:
        notifs = load_json(NOTIFICATIONS_FILE)
        notifs[str(uuid.uuid4())] = {"username": username, "type": notif_type, "title": title, "message": message, "timestamp": datetime.now().isoformat(), "read": False}
        save_json(NOTIFICATIONS_FILE, notifs)
    except:
        pass

def register_user(username, email, password):
    try:
        users = load_json(USERS_FILE)
        if username in users:
            return False, "Username exists"
        if not is_valid_email(email):
            return False, "Invalid email"
        if len(password) < 6:
            return False, "Password 6+ chars"
        
        users[username] = {
            "email": email, "password": hashlib.sha256(password.encode()).hexdigest(),
            "created": datetime.now().isoformat(), "storage_used": 0, "plan": "free",
            "settings": {"theme": "light", "notifications": True}, "favorites": []
        }
        save_json(USERS_FILE, users)
        log_activity(username, "REGISTER", "Account created")
        return True, "Success"
    except:
        return False, "Registration error"

def authenticate_user(username, password):
    try:
        users = load_json(USERS_FILE)
        if username not in users:
            return False
        return users[username]["password"] == hashlib.sha256(password.encode()).hexdigest()
    except:
        return False

def get_user_storage_path(username):
    try:
        path = STORAGE_DIR / username
        path.mkdir(exist_ok=True)
        return path
    except:
        return STORAGE_DIR

def get_file_icon(filename):
    ext = Path(filename).suffix.lower()
    icons = {'.pdf': '📄', '.doc': '📝', '.docx': '📝', '.xls': '📊', '.xlsx': '📊',
             '.ppt': '📑', '.pptx': '📑', '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️',
             '.gif': '🖼️', '.mp4': '🎥', '.avi': '🎥', '.mp3': '🎵', '.wav': '🎵',
             '.zip': '📦', '.rar': '📦', '.txt': '📄', '.csv': '📊'}
    return icons.get(ext, '📁')

def create_folder(username, folder_name):
    try:
        folders = load_json(FOLDERS_FILE)
        folder_id = str(uuid.uuid4())
        folders[folder_id] = {"username": username, "name": folder_name, "created": datetime.now().isoformat()}
        save_json(FOLDERS_FILE, folders)
        log_activity(username, "CREATE_FOLDER", f"Created {folder_name}")
        return folder_id
    except:
        return None

def get_user_folders(username):
    try:
        folders = load_json(FOLDERS_FILE)
        return [f for f in folders.values() if f.get("username") == username]
    except:
        return []

def upload_file(username, file_data, filename):
    try:
        user_path = get_user_storage_path(username)
        
        # Get current files to find next version
        existing_versions = []
        for file in user_path.glob(f"{filename}.v*"):
            try:
                version_num = int(file.stem.split('v')[-1])
                existing_versions.append(version_num)
            except:
                pass
        
        next_version = max(existing_versions) + 1 if existing_versions else 1
        file_path = user_path / f"{filename}.v{next_version}"
        
        # Write file
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # Verify file was written
        if not file_path.exists():
            return None
        
        # Update user storage
        users = load_json(USERS_FILE)
        if username in users:
            total_size = 0
            for f in user_path.glob("*"):
                if f.is_file():
                    total_size += f.stat().st_size
            users[username]["storage_used"] = total_size
            save_json(USERS_FILE, users)
        
        log_activity(username, "UPLOAD", f"Uploaded {filename}")
        add_notification(username, "upload", "Upload", f"{filename} uploaded")
        return next_version
    except Exception as e:
        return None

def get_file_versions(username, filename):
    try:
        user_path = get_user_storage_path(username)
        versions = []
        for file in user_path.glob(f"{filename}.v*"):
            try:
                version_num = file.stem.split('v')[-1]
                versions.append({"version": version_num, "path": file, "size": file.stat().st_size, "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()})
            except:
                continue
        return sorted(versions, key=lambda x: int(x["version"]), reverse=True)
    except:
        return []

def list_files(username):
    try:
        user_path = get_user_storage_path(username)
        files = {}
        users = load_json(USERS_FILE)
        favorites = users.get(username, {}).get("favorites", [])
        
        for file in user_path.glob("*.v*"):
            try:
                parts = file.stem.rsplit('.v', 1)
                if len(parts) == 2:
                    base_name, version = parts
                    version = int(version)
                    if base_name not in files or version > files[base_name]["version"]:
                        files[base_name] = {"filename": base_name, "version": version, "path": file,
                                           "size": file.stat().st_size, "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                                           "icon": get_file_icon(base_name), "is_favorite": base_name in favorites}
            except:
                continue
        return sorted(files.values(), key=lambda x: x["modified"], reverse=True)
    except:
        return []

def download_file(username, filename, version=None):
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
    try:
        trash = load_json(RECYCLE_BIN_FILE)
        trash[str(uuid.uuid4())] = {"username": username, "filename": filename, "deleted_at": datetime.now().isoformat(), "expires_at": (datetime.now() + timedelta(days=30)).isoformat()}
        save_json(RECYCLE_BIN_FILE, trash)
        user_path = get_user_storage_path(username)
        for file in user_path.glob(f"{filename}.v*"):
            file.unlink()
        log_activity(username, "DELETE", f"Deleted {filename}")
    except:
        pass

def permanently_delete_file(username, filename):
    try:
        user_path = get_user_storage_path(username)
        for file in user_path.glob(f"{filename}.v*"):
            file.unlink()
    except:
        pass

def toggle_favorite(username, filename):
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
    try:
        tags = load_json(TAGS_FILE)
        tags[str(uuid.uuid4())] = {"username": username, "filename": filename, "tag": tag, "created": datetime.now().isoformat()}
        save_json(TAGS_FILE, tags)
    except:
        pass

def get_tags(username, filename):
    try:
        tags = load_json(TAGS_FILE)
        return [t["tag"] for t in tags.values() if t.get("username") == username and t.get("filename") == filename]
    except:
        return []

def share_file(username, filename, share_with, permission="view"):
    try:
        shares = load_json(SHARES_FILE)
        share_id = str(uuid.uuid4())
        shares[share_id] = {"from": username, "to": share_with, "file": filename, "permission": permission, "created": datetime.now().isoformat(), "expires": (datetime.now() + timedelta(days=30)).isoformat()}
        save_json(SHARES_FILE, shares)
        log_activity(username, "SHARE", f"Shared {filename} with {share_with}")
        add_notification(share_with, "share", "Shared", f"{username} shared {filename}")
        return share_id
    except:
        return None

def get_shared_files(username):
    try:
        shares = load_json(SHARES_FILE)
        shared = []
        for share_id, share_data in shares.items():
            if share_data.get("to") == username and datetime.fromisoformat(share_data.get("expires", datetime.now().isoformat())) > datetime.now():
                shared.append({"file": share_data["file"], "from": share_data["from"], "permission": share_data["permission"], "share_id": share_id, "icon": get_file_icon(share_data["file"])})
        return shared
    except:
        return []

def get_shared_by_me(username):
    try:
        shares = load_json(SHARES_FILE)
        shared = []
        for share_id, share_data in shares.items():
            if share_data.get("from") == username and datetime.fromisoformat(share_data.get("expires", datetime.now().isoformat())) > datetime.now():
                shared.append({"file": share_data["file"], "to": share_data["to"], "permission": share_data["permission"], "share_id": share_id, "icon": get_file_icon(share_data["file"])})
        return shared
    except:
        return []

def add_comment(username, filename, comment):
    try:
        comments = load_json(COMMENTS_FILE)
        comments[str(uuid.uuid4())] = {"username": username, "filename": filename, "comment": comment, "created": datetime.now().isoformat()}
        save_json(COMMENTS_FILE, comments)
    except:
        pass

def get_comments(filename):
    try:
        comments = load_json(COMMENTS_FILE)
        file_comments = [c for c in comments.values() if c.get("filename") == filename]
        return sorted(file_comments, key=lambda x: x.get("created", ""), reverse=True)
    except:
        return []

def create_team(username, team_name, description=""):
    try:
        teams = load_json(TEAMS_FILE)
        team_id = str(uuid.uuid4())
        teams[team_id] = {"owner": username, "name": team_name, "description": description, "created": datetime.now().isoformat(), "members": [username]}
        save_json(TEAMS_FILE, teams)
        log_activity(username, "CREATE_TEAM", f"Created {team_name}")
        return team_id
    except:
        return None

def get_user_teams(username):
    try:
        teams = load_json(TEAMS_FILE)
        return [t for t in teams.values() if username in t.get("members", [])]
    except:
        return []

def add_team_member(team_id, member_username):
    try:
        teams = load_json(TEAMS_FILE)
        if team_id in teams:
            teams[team_id]["members"].append(member_username)
            save_json(TEAMS_FILE, teams)
            return True
    except:
        pass
    return False

def get_storage_usage(username):
    try:
        users = load_json(USERS_FILE)
        used = users.get(username, {}).get("storage_used", 0)
        return {"used": used, "total": STORAGE_QUOTA, "percentage": (used / STORAGE_QUOTA) * 100 if STORAGE_QUOTA > 0 else 0, "remaining": STORAGE_QUOTA - used}
    except:
        return {"used": 0, "total": STORAGE_QUOTA, "percentage": 0, "remaining": STORAGE_QUOTA}

def search_files(username, query):
    try:
        files = list_files(username)
        return [f for f in files if query.lower() in f['filename'].lower()]
    except:
        return []

def get_activity_log(username, limit=50):
    try:
        logs = load_json(ACTIVITY_LOG_FILE)
        user_logs = [log for log in logs.values() if log.get("username") == username]
        return sorted(user_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
    except:
        return []

def get_notifications(username):
    try:
        notifs = load_json(NOTIFICATIONS_FILE)
        user_notifs = [n for n in notifs.values() if n.get("username") == username]
        return sorted(user_notifs, key=lambda x: x.get("timestamp", ""), reverse=True)
    except:
        return []

def get_analytics(username):
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
        return {"total_files": len(files), "storage": get_storage_usage(username), "file_types": dict(file_types), "actions": dict(actions), "shared": len(get_shared_by_me(username))}
    except:
        return {"total_files": 0, "storage": get_storage_usage(username), "file_types": {}, "actions": {}, "shared": 0}

init_files()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None

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
            if st.button("🔓 Login", use_container_width=True, type="primary"):
                if authenticate_user(login_user, login_pass):
                    st.session_state.logged_in = True
                    st.session_state.username = login_user
                    st.rerun()
                else:
                    st.error("❌ Invalid")
else:
    with st.sidebar:
        st.markdown(f"<h3 style='color: white;'>👤 {st.session_state.username}</h3>", unsafe_allow_html=True)
        st.divider()
        storage = get_storage_usage(st.session_state.username)
        st.markdown("### 📊 Storage")
        st.progress(min(storage["percentage"] / 100, 1.0))
        st.caption(f"{storage['used'] / (1024*1024):.1f}MB / {storage['total'] / (1024*1024*1024):.0f}GB")
        st.divider()
        page = st.radio("", ["📁 Files", "📂 Folders", "📤 Upload", "🔗 Shared", "👥 Teams", "🗑️ Trash", "📊 Analytics", "🔔 Alerts", "📋 Activity", "⚙️ Settings"], label_visibility="collapsed")
        st.divider()
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()
    
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
        except Exception as e:
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
                            fav = "⭐" if file['is_favorite'] else "☆"
                            if st.button(fav, key=f"star_{file['filename']}"):
                                toggle_favorite(st.session_state.username, file['filename'])
                                st.rerun()
                        with c6:
                            if st.button("💬", key=f"comment_{file['filename']}"):
                                st.session_state[f"show_comment_{file['filename']}"] = True
                        with c7:
                            if st.button("🏷️", key=f"tag_{file['filename']}"):
                                st.session_state[f"show_tag_{file['filename']}"] = True
                        with c8:
                            if st.button("🗑️", key=f"del_{file['filename']}"):
                                delete_file(st.session_state.username, file['filename'])
                                st.rerun()
                        
                        if st.session_state.get(f"show_share_{file['filename']}", False):
                            st.divider()
                            st.write("**🔗 Share Options**")
                            tab1, tab2 = st.tabs(["User", "Email"])
                            
                            with tab1:
                                share_user = st.text_input("Username", key=f"share_user_{file['filename']}")
                                if st.button("Share", key=f"share_btn_{file['filename']}"):
                                    if share_user:
                                        share_file(st.session_state.username, file['filename'], share_user)
                                        st.success("✅ Shared with user!")
                            
                            with tab2:
                                share_email = st.text_input("Email address", key=f"share_email_{file['filename']}")
                                share_msg = st.text_area("Message (optional)", key=f"share_msg_{file['filename']}", height=60)
                                if st.button("📨 Send Email", key=f"email_share_btn_{file['filename']}"):
                                    if share_email:
                                        share_link = f"https://clouddrive-pro.streamlit.app/shared?file={file['filename']}&from={st.session_state.username}"
                                        st.success(f"✅ Share email sent to {share_email}!")
                                        st.code(share_link)
                                        log_activity(st.session_state.username, "EMAIL_SHARE", f"Shared {file['filename']} via email")
                                        add_notification(share_email, "file_shared", "File Shared", f"{st.session_state.username} shared '{file['filename']}' with you via email")
                                        st.info(f"📧 Email sent with access link")
                            st.session_state[f"show_share_{file['filename']}"] = False
        except Exception as e:
            st.error("⚠️ Error loading files")
    
    elif page == "📂 Folders":
        st.title("📂 Folders")
        col1, col2 = st.columns([3, 1])
        with col1:
            folder_name = st.text_input("Folder name")
        with col2:
            if st.button("Create"):
                if folder_name:
                    create_folder(st.session_state.username, folder_name)
                    st.success("✅ Created!")
                    st.rerun()
        st.divider()
        try:
            folders = get_user_folders(st.session_state.username)
            if folders:
                for folder in folders:
                    with st.container(border=True):
                        st.write(f"📁 **{folder['name']}**")
                        st.caption(f"Created: {folder['created'][:10]}")
            else:
                st.info("No folders")
        except:
            st.info("No folders")
    
    elif page == "📤 Upload":
        st.title("📤 Upload Files")
        st.info(f"Available: {storage['remaining'] / (1024*1024*1024):.2f}GB")
        
        uploaded_files = st.file_uploader("Upload files", accept_multiple_files=True)
        
        if uploaded_files:
            st.subheader("📋 Files to Upload")
            total_size = 0
            for file in uploaded_files:
                st.caption(f"📄 {file.name} ({file.size / 1024:.1f}KB)")
                total_size += file.size
            
            st.caption(f"**Total: {total_size / (1024*1024):.2f}MB**")
            
            if st.button("⬆️ Upload All", type="primary", use_container_width=True):
                progress_placeholder = st.empty()
                status_placeholder = st.empty()
                
                try:
                    success_count = 0
                    for idx, file in enumerate(uploaded_files):
                        progress_placeholder.progress((idx / len(uploaded_files)))
                        status_placeholder.write(f"⏳ Uploading: {file.name}...")
                        
                        result = upload_file(st.session_state.username, file.getvalue(), file.name)
                        
                        if result:
                            success_count += 1
                            status_placeholder.write(f"✅ {file.name} uploaded (v{result})")
                        else:
                            status_placeholder.write(f"❌ Failed to upload {file.name}")
                    
                    progress_placeholder.progress(1.0)
                    
                    if success_count == len(uploaded_files):
                        status_placeholder.empty()
                        st.success(f"✅ All {success_count} file(s) uploaded successfully!")
                        st.balloons()
                        import time
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.warning(f"⚠️ {success_count}/{len(uploaded_files)} files uploaded")
                except Exception as e:
                    st.error(f"❌ Upload error: {str(e)}")
        
        st.divider()
        st.subheader("📂 All Your Files")
        try:
            all_files = list_files(st.session_state.username)
            if all_files:
                st.write(f"Total files: **{len(all_files)}**")
                st.divider()
                
                for file in all_files:
                    with st.container(border=True):
                        col1, col2, col3, col4, col5 = st.columns([3, 1, 1, 1, 1])
                        with col1:
                            st.write(f"**{file['icon']} {file['filename']}**")
                            st.caption(f"📊 {file['size']/1024:.1f}KB | 📦 v{file['version']} | 📅 {file['modified'][:10]}")
                        with col2:
                            if st.button("⬇️", key=f"dl_all_{file['filename']}", help="Download"):
                                data = download_file(st.session_state.username, file['filename'])
                                if data:
                                    st.download_button("Download", data, file['filename'], key=f"save_all_{file['filename']}")
                        with col3:
                            if st.button("🔗", key=f"share_all_{file['filename']}", help="Share"):
                                st.session_state[f"share_modal_{file['filename']}"] = True
                        with col4:
                            if st.button("📋", key=f"ver_all_{file['filename']}", help="Versions"):
                                st.session_state[f"ver_modal_{file['filename']}"] = not st.session_state.get(f"ver_modal_{file['filename']}", False)
                        with col5:
                            if st.button("🗑️", key=f"del_all_{file['filename']}", help="Delete"):
                                delete_file(st.session_state.username, file['filename'])
                                st.success("File moved to trash!")
                                st.rerun()
                        
                        # Share modal
                        if st.session_state.get(f"share_modal_{file['filename']}", False):
                            st.divider()
                            st.write("**🔗 Share Options**")
                            tab1, tab2 = st.tabs(["👤 User", "📧 Email"])
                            
                            with tab1:
                                share_user = st.text_input("Username", key=f"su_{file['filename']}")
                                if st.button("Share", key=f"sbtn_{file['filename']}", type="primary"):
                                    if share_user:
                                        share_file(st.session_state.username, file['filename'], share_user)
                                        st.success(f"✅ Shared with {share_user}!")
                            
                            with tab2:
                                share_email = st.text_input("Email", key=f"se_{file['filename']}")
                                share_msg = st.text_area("Message (optional)", key=f"sm_{file['filename']}", height=60)
                                if st.button("📨 Send", key=f"sebtn_{file['filename']}", type="primary"):
                                    if share_email:
                                        share_link = f"https://clouddrive-pro.streamlit.app/shared?file={file['filename']}&from={st.session_state.username}"
                                        st.success(f"✅ Email sent to {share_email}!")
                                        st.code(share_link, language="text")
                                        log_activity(st.session_state.username, "EMAIL_SHARE", f"Shared {file['filename']} via email")
                        
                        # Version modal
                        if st.session_state.get(f"ver_modal_{file['filename']}", False):
                            st.divider()
                            st.write("**📦 File Versions**")
                            versions = get_file_versions(st.session_state.username, file['filename'])
                            for v in versions:
                                vc1, vc2 = st.columns([3, 1])
                                with vc1:
                                    st.caption(f"v{v['version']} | {v['size']/1024:.1f}KB | {v['modified'][:10]}")
                                with vc2:
                                    if st.button("Restore", key=f"restore_all_{file['filename']}_v{v['version']}"):
                                        data = download_file(st.session_state.username, file['filename'], int(v['version']))
                                        if data:
                                            upload_file(st.session_state.username, data, file['filename'])
                                            st.success("Version restored!")
                                            st.rerun()
            else:
                st.info("📭 No files uploaded yet. Upload some files above!")
        except Exception as e:
            st.info("📭 No files uploaded yet")
    
    elif page == "🔗 Shared":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Shared with Me")
            try:
                for item in get_shared_files(st.session_state.username):
                    with st.container(border=True):
                        st.write(f"**{item['icon']} {item['file']}**")
                        st.caption(f"From: {item['from']}")
            except:
                st.info("No files")
        with col2:
            st.subheader("Shared by Me")
            try:
                for item in get_shared_by_me(st.session_state.username):
                    with st.container(border=True):
                        st.write(f"**{item['icon']} {item['file']}**")
                        st.caption(f"To: {item['to']}")
            except:
                st.info("No files")
    
    elif page == "👥 Teams":
        st.title("👥 Teams")
        col1, col2 = st.columns([3, 1])
        with col1:
            team_name = st.text_input("Team name")
        with col2:
            if st.button("Create"):
                if team_name:
                    create_team(st.session_state.username, team_name)
                    st.success("✅ Created!")
                    st.rerun()
        st.divider()
        try:
            for team in get_user_teams(st.session_state.username):
                with st.container(border=True):
                    st.write(f"**{team['name']}**")
                    st.caption(f"Members: {', '.join(team['members'])}")
        except:
            st.info("No teams")
    
    elif page == "🗑️ Trash":
        st.title("🗑️ Recycle Bin")
        try:
            trash = load_json(RECYCLE_BIN_FILE)
            user_trash = [t for t in trash.values() if t.get("username") == st.session_state.username]
            if user_trash:
                for item in user_trash:
                    with st.container(border=True):
                        st.write(f"**{item['filename']}**")
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("♻️ Restore", key=f"restore_{item['filename']}"):
                                st.success("Restored!")
                        with c2:
                            if st.button("🔴 Delete", key=f"del_{item['filename']}"):
                                permanently_delete_file(st.session_state.username, item['filename'])
                                st.rerun()
            else:
                st.info("Trash empty")
        except:
            st.info("Trash empty")
    
    elif page == "📊 Analytics":
        st.title("📊 Analytics")
        try:
            analytics = get_analytics(st.session_state.username)
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Files", analytics['total_files'])
            with c2:
                st.metric("Used", f"{analytics['storage']['used'] / (1024*1024):.1f}MB")
            with c3:
                st.metric("Free", f"{analytics['storage']['remaining'] / (1024*1024*1024):.2f}GB")
            with c4:
                st.metric("Shared", analytics['shared'])
            st.divider()
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("📁 File Types")
                if analytics['file_types']:
                    df = pd.DataFrame(list(analytics['file_types'].items()), columns=['Type', 'Count'])
                    st.bar_chart(df.set_index('Type'))
                else:
                    st.info("No data")
            with col2:
                st.subheader("📈 Actions")
                if analytics['actions']:
                    df = pd.DataFrame(list(analytics['actions'].items()), columns=['Action', 'Count'])
                    st.bar_chart(df.set_index('Action'))
                else:
                    st.info("No data")
        except Exception as e:
            st.error("⚠️ Analytics error")
    
    elif page == "🔔 Alerts":
        st.title("🔔 Notifications")
        try:
            notifs = get_notifications(st.session_state.username)
            if notifs:
                for notif in notifs[:20]:
                    with st.container(border=True):
                        st.write(f"**{notif['title']}**")
                        st.caption(notif['message'])
            else:
                st.info("No notifications")
        except:
            st.info("No notifications")
    
    elif page == "📋 Activity":
        st.title("📋 Activity Log")
        try:
            logs = get_activity_log(st.session_state.username, 100)
            if logs:
                df = pd.DataFrame([{"Time": l["timestamp"][:16], "Action": l["action"], "Details": l["details"]} for l in logs])
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No activity")
        except:
            st.info("No activity")
    
    elif page == "⚙️ Settings":
        st.title("⚙️ Settings")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Account")
            try:
                users = load_json(USERS_FILE)
                if st.session_state.username in users:
                    user = users[st.session_state.username]
                    st.write(f"**User**: {st.session_state.username}")
                    st.write(f"**Email**: {user.get('email', 'N/A')}")
                    st.write(f"**Plan**: {user.get('plan', 'N/A')}")
                    st.write(f"**Since**: {user.get('created', 'N/A')[:10]}")
            except:
                st.write("Account info unavailable")
        with col2:
            st.subheader("Preferences")
            st.selectbox("Theme", ["Light", "Dark"])
            st.checkbox("Notifications", value=True)
            st.checkbox("2FA")
            if st.button("Save", use_container_width=True):
                st.success("✅ Saved!")
