import logging
import secrets
import datetime
from typing import Optional
from ..database.dataBase import DatabaseManager

class SessionManager:
    """会话管理类，处理用户会话相关逻辑"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def create_session(self, username: str) -> str:
        """为用户创建新的session"""
        try:
            session_id = secrets.token_hex(32)
            
            # 首先使旧的session失效
            self.db.invalidate_user_sessions(username)
            
            # 创建新的session记录
            created_at = datetime.datetime.now()
            expires_at = created_at + datetime.timedelta(hours=24)
            
            session_data = {
                'session_id': session_id,
                'username': username,
                'created_at': created_at.isoformat(),
                'expires_at': expires_at.isoformat(),
                'is_active': 1
            }
            
            self.db.insert('session_ID', session_data)
            
            return session_id
        except Exception as e:
            logging.error(f"Create session error: {e}")
            raise e
    
    def validate_session(self, session_id: str) -> Optional[str]:
        """验证session是否有效，返回用户名或None"""
        try:
            username = self.db.validate_session(session_id)
            return username
        except Exception as e:
            logging.error(f"Validate session error: {e}")
            return None
    
    def invalidate_session(self, session_id: str) -> bool:
        """使session失效"""
        try:
            return self.db.invalidate_session(session_id)
        except Exception as e:
            logging.error(f"Invalidate session error: {e}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """清理过期的session"""
        try:
            return self.db.cleanup_expired_sessions()
        except Exception as e:
            logging.error(f"Cleanup expired sessions error: {e}")
            return 0