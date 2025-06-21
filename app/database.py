import sqlite3
from datetime import datetime, timedelta
import hashlib
import uuid

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """初始化数据库表"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建用户表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建会话表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Database initialization error: {e}")

    def create_user(self, username, password, email=None):
        """创建新用户"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
            ''', (username, password_hash, email))
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            print(f"Create user error: {e}")
            return False

    def verify_user(self, username, password):
        """验证用户登录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            cursor.execute('''
                SELECT username FROM users 
                WHERE username = ? AND password_hash = ?
            ''', (username, password_hash))
            
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
            
        except Exception as e:
            print(f"Verify user error: {e}")
            return False

    def create_session(self, username, session_id, ip_address=None, user_agent=None):
        """创建用户会话"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            now = datetime.now()
            expires_at = now + timedelta(hours=24)  # 会话24小时有效
            
            cursor.execute('''
                INSERT INTO sessions (session_id, username, created_at, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, username, now, expires_at, ip_address, user_agent))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"Create session error: {e}")
            return False

    def get_session(self, session_id):
        """获取会话信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, expires_at FROM sessions 
                WHERE session_id = ? AND is_active = 1
            ''', (session_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                username, expires_at = result
                expires_time = datetime.fromisoformat(expires_at)
                if expires_time > datetime.now():
                    return username
                else:
                    self.invalidate_session(session_id)
            
            return None
            
        except Exception as e:
            print(f"Get session error: {e}")
            return None

    def invalidate_session(self, session_id):
        """使会话失效"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE sessions SET is_active = 0 
                WHERE session_id = ?
            ''', (session_id,))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"Invalidate session error: {e}")
            return False