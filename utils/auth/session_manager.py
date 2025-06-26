import logging
from typing import Optional
from ..database.dataBase import DatabaseManager

class SessionManager:
    """会话管理类，处理用户会话相关逻辑"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
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