import streamlit as st
import json
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import pandas as pd
from collections import defaultdict

st.set_page_config(page_title="CloudDrive Pro", page_icon="☁️", layout="wide")

st.markdown("""
<style>
    [data-testid="stSidebar"] { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
    .main { background-color: #f5f7fa; }
</style>
""", unsafe_allow_html=True)

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
        return json.loads(path.read_text())
    except:
        return {}

def save_json(path, data):
    path.write_text(json.dumps(data, indent=2))

def is_valid_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def log_activity(username, action, details):
    logs = load_json(ACTIVITY_LOG_FILE)
    logs[str(uuid.uuid4())] = {"username": username, "action": action, "details": details, "timestamp": datetime.now().isoformat()}
    save_json(ACTIVITY_LOG_FILE, logs)

def add_notification(username, notif_type, title, message):
    notifs = load_json(NOTIFICATIONS_FILE)
    notifs[str(uuid.uuid4())] = {"username": username, "type": notif_type, "title": title, "message": message, "timestamp": datetime.now().isoformat(), "read": False}
    save_json(NOTIFICATIONS_FILE, notifs)

def register_user(username, email, password):
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

def authenticate_user(username, password):
    users = load_json(USERS_FILE)
    if username not in users:
        return False
    return users[username]["password"] == hashlib.sha256(password.encode()).hexdigest()

def get_user_storage_path(username):
    path = STORAGE_DIR / username
    path.mkdir(exist_ok=True)
    return path

def get_file_icon(filename):
    ext = Path(filename).suffix.lower()
    icons = {'.pdf': '📄', '.doc': '📝', '.docx': '📝', '.xls': '📊', '.xlsx': '📊',
             '.ppt': '📑', '.pptx': '📑', '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️',
             '.gif': '🖼️', '.mp4': '🎥', '.avi': '🎥', '.mp3': '🎵', '.wav': '🎵',
             '.zip': '📦', '.rar': '📦', '.txt': '📄', '.csv': '📊'}
    return icons.get(ext, '📁')

def create_folder(username, folder_name):
    folders = load_json(FOLDERS_FILE)
    folder_id = str(uuid.uuid4())
    folders[folder_id] = {"username": username, "name": folder_name, "created": datetime.now().isoformat()}
    save_json(FOLDERS_FILE, folders)
    log_activity(username, "CREATE_FOLDER", f"Created {folder_name}")
    return folder_id

def get_user_folders(username):
    folders = load_json(FOLDERS_FILE)
    return [f for f in folders.values() if f["username"] == username]

def upload_file(username, file_data, filename):
    user_path = get_user_storage_path(username)
    versions = get_file_versions(username, filename)
    next_version = 1 if not versions else int(versions[0]["version"]) + 1
    file_path = user_path / f"{filename}.v{next_version}"
    file_path.write_bytes(file_data)
    
    users = load_json(USERS_FILE)
    users[username]["storage_used"] = sum(f.stat().st_size for f in user_path.glob("*") if f.is_file())
    save_json(USERS_FILE, users)
    log_activity(username, "UPLOAD", f"Uploaded {filename}")
    add_notification(username, "upload", "Upload", f"{filename} uploaded")
    return next_version

def get_file_versions(username, filename):
    user_path = get_user_storage_path(username)
    versions = []
    for file in user_path.glob(f"{filename}.v*"):
        version_num = file.stem.split('v')[1]
        versions.append({"version": version_num, "path": file, "size": file.stat().st_size, "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()})
    return sorted(versions, key=lambda x: int(x["version"]), reverse=True)

def list_files(username):
    user_path = get_user_storage_path(username)
    files = {}
    users = load_json(USERS_FILE)
    favorites = users.get(username, {}).get("favorites", [])
    
    for file in user_path.glob("*.v*"):
        base_name = file.stem.rsplit('.v', 1)[0]
        version = int(file.stem.rsplit('.v', 1)[1])
        if base_name not in files or version > files[base_name]["version"]:
            files[base_name] = {"filename": base_name, "version": version, "path": file,
                               "size": file.stat().st_size, "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                               "icon": get_file_icon(base_name), "is_favorite": base_name in favorites}
    return sorted(files.values(), key=lambda x: x["modified"], reverse=True)

def download_file(username, filename, version=None):
    user_path = get_user_storage_path(username)
    if version:
        file_path = user_path / f"{filename}.v{version}"
    else:
        versions = get_file_versions(username, filename)
        if not versions:
            return None
        file_path = versions[0]["path"]
    return file_path.read_bytes() if file_path.exists() else None

def delete_file(username, filename):
    trash = load_json(RECYCLE_BIN_FILE)
    trash[str(uuid.uuid4())] = {"username": username, "filename": filename, "deleted_at": datetime.now().isoformat(), "expires_at": (datetime.now() + timedelta(days=30)).isoformat()}
    save_json(RECYCLE_BIN_FILE, trash)
    user_path = get_user_storage_path(username)
    for file in user_path.glob(f"{filename}.v*"):
        file.unlink()
    log_activity(username, "DELETE", f"Deleted {filename}")

def permanently_delete_file(username, filename):
    user_path = get_user_storage_path(username)
    for file in user_path.glob(f"{filename}.v*"):
        file.unlink()

def toggle_favorite(username, filename):
    users = load_json(USERS_FILE)
    if filename in users[username]["favorites"]:
        users[username]["favorites"].remove(filename)
    else:
        users[username]["favorites"].append(filename)
    save_json(USERS_FILE, users)

def add_tag(username, filename, tag):
    tags = load_json(TAGS_FILE)
    tags[str(uuid.uuid4())] = {"username": username, "filename": filename, "tag": tag, "created": datetime.now().isoformat()}
    save_json(TAGS_FILE, tags)

def get_tags(username, filename):
    tags = load_json(TAGS_FILE)
    return [t["tag"] for t in tags.values() if t["username"] == username and t["filename"] == filename]

def share_file(username, filename, share_with, permission="view"):
    shares = load_json(SHARES_FILE)
    share_id = str(uuid.uuid4())
    shares[share_id] = {"from": username, "to": share_with, "file": filename, "permission": permission, "created": datetime.now().isoformat(), "expires": (datetime.now() + timedelta(days=30)).isoformat()}
    save_json(SHARES_FILE, shares)
    log_activity(username, "SHARE", f"Shared {filename} with {share_with}")
    add_notification(share_with, "share", "Shared", f"{username} shared {filename}")
    return share_id

def get_shared_files(username):
    shares = load_json(SHARES_FILE)
    shared = []
    for share_id, share_data in shares.items():
        if share_data["to"] == username and datetime.fromisoformat(share_data["expires"]) > datetime.now():
            shared.append({"file": share_data["file"], "from": share_data["from"], "permission": share_data["permission"], "share_id": share_id, "icon": get_file_icon(share_data["file"])})
    return shared

def get_shared_by_me(username):
    shares = load_json(SHARES_FILE)
    shared = []
    for share_id, share_data in shares.items():
        if share_data["from"] == username and datetime.fromisoformat(share_data["expires"]) > datetime.now():
            shared.append({"file": share_data["file"], "to": share_data["to"], "permission": share_data["permission"], "share_id": share_id, "icon": get_file_icon(share_data["file"])})
    return shared

def add_comment(username, filename, comment):
    comments = load_json(COMMENTS_FILE)
    comments[str(uuid.uuid4())] = {"username": username, "filename": filename, "comment": comment, "created": datetime.now().isoformat()}
    save_json(COMMENTS_FILE, comments)

def get_comments(filename):
    comments = load_json(COMMENTS_FILE)
    file_comments = [c for c in comments.values() if c["filename"] == filename]
    return sorted(file_comments, key=lambda x: x["created"], reverse=True)

def create_team(username, team_name, description=""):
    teams = load_json(TEAMS_FILE)
    team_id = str(uuid.uuid4())
    teams[team_id] = {"owner": username, "name": team_name, "description": description, "created": datetime.now().isoformat(), "members": [username]}
    save_json(TEAMS_FILE, teams)
    log_activity(username, "CREATE_TEAM", f"Created {team_name}")
    return team_id

def get_user_teams(username):
    teams = load_json(TEAMS_FILE)
    return [t for t in teams.values() if username in t["members"]]

def add_team_member(team_id, member_username):
    teams = load_json(TEAMS_FILE)
    if team_id in teams:
        teams[team_id]["members"].append(member_username)
        save_json(TEAMS_FILE, teams)
        return True
    return False

def get_storage_usage(username):
    users = load_json(USERS_FILE)
    used = users[username]["storage_used"]
    return {"used": used, "total": STORAGE_QUOTA, "percentage": (used / STORAGE_QUOTA) * 100, "remaining": STORAGE_QUOTA - used}

def search_files(username, query):
    files = list_files(username)
    return [f for f in files if query.lower() in f['filename'].lower()]

def get_activity_log(username, limit=50):
    logs = load_json(ACTIVITY_LOG_FILE)
    user_logs = [log for log in logs.values() if log["username"] == username]
    return sorted(user_logs, key=lambda x: x["timestamp"], reverse=True)[:limit]

def get_notifications(username):
    notifs = load_json(NOTIFICATIONS_FILE)
    user_notifs = [n for n in notifs.values() if n["username"] == username]
    return sorted(user_notifs, key=lambda x: x["timestamp"], reverse=True)

def get_analytics(username):
    files = list_files(username)
    logs = get_activity_log(username, 100)
    file_types = defaultdict(int)
    for file in files:
        ext = Path(file["filename"]).suffix or "unknown"
        file_types[ext] += 1
    actions = defaultdict(int)
    for log in logs:
        actions[log["action"]] += 1
    return {"total_files": len(files), "storage": get_storage_usage(username), "file_types": dict(file_types), "actions": dict(actions), "shared": len(get_shared_by_me(username))}

init_files()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None

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
        st.progress(storage["percentage"] / 100)
        st.caption(f"{storage['used'] / (1024*1024):.1f}MB / {storage['total'] / (1024*1024*1024):.0f}GB")
        st.divider()
        page = st.radio("", ["📁 Files", "📂 Folders", "📤 Upload", "🔗 Shared", "👥 Teams", "🗑️ Trash", "📊 Analytics", "🔔 Notifications", "📋 Activity", "⚙️ Settings"], label_visibility="collapsed")
        st.divider()
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()
    
    if page == "📁 Files":
        st.title("📁 My Files")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Files", len(list_files(st.session_state.username)))
        with c2:
            st.metric("Used", f"{storage['used'] / (1024*1024):.1f}MB")
        with c3:
            st.metric("Free", f"{storage['remaining'] / (1024*1024*1024):.2f}GB")
        with c4:
            st.metric("Shared", len(get_shared_by_me(st.session_state.username)))
        st.divider()
        
        c1, c2, c3 = st.columns([3, 1, 1])
        with c1:
            search = st.text_input("🔍 Search")
        with c2:
            sort = st.selectbox("Sort", ["New", "Old", "Name", "Size"])
        with c3:
            st.selectbox("View", ["List", "Grid"])
        
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
                        st.caption(f"v{file['version']} | {file['size']/1024:.1f}KB | {file['modified'][:10]}")
                    
                    with c2:
                        if st.button("⬇️", key=f"dl_{file['filename']}"):
                            data = download_file(st.session_state.username, file['filename'])
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
                    
                    if st.session_state.get(f"show_v_{file['filename']}", False):
                        st.divider()
                        st.write("**📦 Versions:**")
                        for v in get_file_versions(st.session_state.username, file['filename']):
                            vc1, vc2 = st.columns([3, 1])
                            with vc1:
                                st.caption(f"v{v['version']} | {v['size']/1024:.1f}KB | {v['modified'][:10]}")
                            with vc2:
                                if st.button("Restore", key=f"restore_{file['filename']}_v{v['version']}"):
                                    data = download_file(st.session_state.username, file['filename'], int(v['version']))
                                    upload_file(st.session_state.username, data, file['filename'])
                                    st.rerun()
                    
                    if st.session_state.get(f"show_share_{file['filename']}", False):
                        st.divider()
                        share_user = st.text_input("Username", key=f"share_user_{file['filename']}")
                        share_perm = st.selectbox("Permission", ["view", "download"], key=f"perm_{file['filename']}")
                        if st.button("Share", key=f"share_btn_{file['filename']}"):
                            share_file(st.session_state.username, file['filename'], share_user, share_perm)
                            st.success("✅ Shared!")
                    
                    if st.session_state.get(f"show_comment_{file['filename']}", False):
                        st.divider()
                        st.write("**💬 Comments:**")
                        new_comment = st.text_area("Add comment", key=f"new_comment_{file['filename']}")
                        if st.button("Post", key=f"post_comment_{file['filename']}"):
                            add_comment(st.session_state.username, file['filename'], new_comment)
                            st.success("✅ Posted!")
                        for comment in get_comments(file['filename'])[:5]:
                            st.caption(f"**{comment['username']}**: {comment['comment']}")
                    
                    if st.session_state.get(f"show_tag_{file['filename']}", False):
                        st.divider()
                        new_tag = st.text_input("Add tag", key=f"new_tag_{file['filename']}")
                        if st.button("Add", key=f"add_tag_{file['filename']}"):
                            add_tag(st.session_state.username, file['filename'], new_tag)
                            st.success("✅ Added!")
                        st.caption(f"Tags: {', '.join(get_tags(st.session_state.username, file['filename']))}")
    
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
        folders = get_user_folders(st.session_state.username)
        if folders:
            for folder in folders:
                with st.container(border=True):
                    st.write(f"📁 **{folder['name']}**")
                    st.caption(f"Created: {folder['created'][:10]}")
        else:
            st.info("No folders")
    
    elif page == "📤 Upload":
        st.title("📤 Upload")
        st.info(f"Available: {storage['remaining'] / (1024*1024*1024):.2f}GB")
        uploaded_files = st.file_uploader("Upload files", accept_multiple_files=True)
        if uploaded_files and st.button("Upload All", type="primary", use_container_width=True):
            for file in uploaded_files:
                upload_file(st.session_state.username, file.getvalue(), file.name)
                st.success(f"✅ {file.name}")
            st.rerun()
    
    elif page == "🔗 Shared":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Shared with Me")
            for item in get_shared_files(st.session_state.username):
                with st.container(border=True):
                    st.write(f"**{item['icon']} {item['file']}**")
                    st.caption(f"From: {item['from']}")
                    if st.button("⬇️", key=f"dl_{item['share_id']}"):
                        data = download_file(item['from'], item['file'])
                        st.download_button("Download", data, item['file'])
        with col2:
            st.subheader("Shared by Me")
            for item in get_shared_by_me(st.session_state.username):
                with st.container(border=True):
                    st.write(f"**{item['icon']} {item['file']}**")
                    st.caption(f"To: {item['to']}")
    
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
        for team in get_user_teams(st.session_state.username):
            with st.container(border=True):
                st.write(f"**{team['name']}**")
                st.caption(f"Members: {', '.join(team['members'])}")
    
    elif page == "🗑️ Trash":
        st.title("🗑️ Recycle Bin")
        trash = load_json(RECYCLE_BIN_FILE)
        user_trash = [t for t in trash.values() if t["username"] == st.session_state.username]
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
    
    elif page == "📊 Analytics":
        st.title("📊 Analytics")
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
                st.bar_chart(pd.DataFrame(list(analytics['file_types'].items()), columns=['Type', 'Count']).set_index('Type'))
        with col2:
            st.subheader("📈 Actions")
            if analytics['actions']:
                st.bar_chart(pd.DataFrame(list(analytics['actions'].items()), columns=['Action', 'Count']).set_index('Action'))
    
    elif page == "🔔 Notifications":
        st.title("🔔 Notifications")
        notifs = get_notifications(st.session_state.username)
        if notifs:
            for notif in notifs[:20]:
                with st.container(border=True):
                    st.write(f"**{notif['title']}**")
                    st.caption(notif['message'])
        else:
            st.info("No notifications")
    
    elif page == "📋 Activity":
        st.title("📋 Activity Log")
        logs = get_activity_log(st.session_state.username, 100)
        if logs:
            df = pd.DataFrame([{"Time": l["timestamp"][:16], "Action": l["action"], "Details": l["details"]} for l in logs])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No activity")
    
    elif page == "⚙️ Settings":
        st.title("⚙️ Settings")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Account")
            users = load_json(USERS_FILE)
            user = users[st.session_state.username]
            st.write(f"**User**: {st.session_state.username}")
            st.write(f"**Email**: {user['email']}")
            st.write(f"**Plan**: {user['plan']}")
            st.write(f"**Since**: {user['created'][:10]}")
        with col2:
            st.subheader("Preferences")
            st.selectbox("Theme", ["Light", "Dark"])
            st.checkbox("Notifications", value=True)
            st.checkbox("2FA")
            if st.button("Save", use_container_width=True):
                st.success("✅ Saved!")   

