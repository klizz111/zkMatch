import sqlite3
from typing import List, Tuple, Any, Optional
import logging
import secrets
import datetime
from ..mathlib.elgamal import ElGamal

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection = None
        self.isInitialized = False
        
    def initialize(self):
        """判断是否存在表user_data和account_data"""
        if not self.isInitialized:
            try:
                self.connect()
                self.create_table("user_data", 
                                """id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                username TEXT NOT NULL UNIQUE, 
                                nickname TEXT NOT NULL, 
                                age INTEGER,
                                contact_info TEXT,
                                personal_info TEXT,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"""
                )
                self.create_table("account_data",
                                  """id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                  username TEXT NOT NULL UNIQUE, 
                                  p TEXT NOT NULL, 
                                  g TEXT NOT NULL,
                                  q TEXT NOT NULL, 
                                  y TEXT NOT NULL, 
                                  seed_hash TEXT NOT NULL,
                                  compressed_credential TEXT NOT NULL,
                                  bits INTEGER DEFAULT 256,
                                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"""
                )
                self.create_table("session_ID",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                session_id TEXT NOT NULL UNIQUE,
                                username TEXT NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                expires_at TIMESTAMP NOT NULL,
                                is_active INTEGER DEFAULT 1,
                                FOREIGN KEY (username) REFERENCES user_data(username)"""
                )
                
                # account_data中添加root用户，将root的p,g,q,y设置为系统全局的群参数
                elgamal = ElGamal(bits=512)
                elgamal.keygen()
                root_data = {
                    'username': 'root',
                    'p': str(elgamal.p),
                    'g': str(elgamal.g),
                    'q': str(elgamal.q),
                    'y': str(elgamal.y),
                    'seed_hash': '',
                    'compressed_credential': '',
                    'bits': 512
                }
                self.insert("account_data", root_data)
                
                self.isInitialized = True
                self.disconnect()
            except sqlite3.Error as e:
                logging.error(f"Database initialization error: {e}")
                raise
    
    def connect(self):
        """连接到SQLite数据库"""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  
            return self.connection
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {e}")
            raise
        
    def disconnect(self):
        """关闭数据库连接"""
        if self.connection:
            self.connection.close()
            self.connection = None
            
  
    def create_table(self, table_name: str, columns: str):
        """
        创建表
        
        Args:
            table_name: 表名
            columns: 列定义，例如: "id INTEGER PRIMARY KEY, name TEXT, age INTEGER"
        """
        try:
            cursor = self.connection.cursor()
            columns = columns.replace('\n', ' ').replace('\r', ' ')
            sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
            cursor.execute(sql)
            self.connection.commit()
            print(f"表 {table_name} 创建成功")
        except sqlite3.Error as e:
            print(f"创建表失败: {e}")
            raise
    
    def insert(self, table_name: str, data: dict) -> int:
        """
        插入数据
        
        Args:
            table_name: 表名
            data: 要插入的数据字典
            
        Returns:
            插入行的ID
        """
        try:
            cursor = self.connection.cursor()
            columns = ', '.join(data.keys())
            placeholders = ', '.join(['?' for _ in data])
            sql = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
            cursor.execute(sql, tuple(data.values()))
            self.connection.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"插入数据失败: {e}")
            raise
    
    def select(self, table_name: str, where_clause: str = "", params: tuple = ()) -> List[sqlite3.Row]:
        """
        查询数据
        
        Args:
            table_name: 表名
            where_clause: WHERE条件子句
            params: 参数元组
            
        Returns:
            查询结果列表
        """
        try:
            cursor = self.connection.cursor()
            sql = f"SELECT * FROM {table_name}"
            if where_clause:
                sql += f" WHERE {where_clause}"
            cursor.execute(sql, params)
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"查询数据失败: {e}")
            raise
    
    def update(self, table_name: str, data: dict, where_clause: str, params: tuple = ()) -> int:
        """
        更新数据
        
        Args:
            table_name: 表名
            data: 要更新的数据字典
            where_clause: WHERE条件子句
            params: WHERE条件参数
            
        Returns:
            受影响的行数
        """
        try:
            cursor = self.connection.cursor()
            set_clause = ', '.join([f"{key} = ?" for key in data.keys()])
            sql = f"UPDATE {table_name} SET {set_clause} WHERE {where_clause}"
            all_params = tuple(data.values()) + params
            cursor.execute(sql, all_params)
            self.connection.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            print(f"更新数据失败: {e}")
            raise
    
    def delete(self, table_name: str, where_clause: str, params: tuple = ()) -> int:
        """
        删除数据
        
        Args:
            table_name: 表名
            where_clause: WHERE条件子句
            params: 参数元组
            
        Returns:
            受影响的行数
        """
        try:
            cursor = self.connection.cursor()
            sql = f"DELETE FROM {table_name} WHERE {where_clause}"
            cursor.execute(sql, params)
            self.connection.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            print(f"删除数据失败: {e}")
            raise
    
    def execute_custom_sql(self, sql: str, params: tuple = ()) -> Any:
        """
        执行自定义SQL语句
        
        Args:
            sql: SQL语句
            params: 参数元组
            
        Returns:
            查询结果或None
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(sql, params)
            
            # 如果是SELECT语句，返回结果
            if sql.strip().upper().startswith('SELECT'):
                return cursor.fetchall()
            else:
                self.connection.commit()
                return cursor.rowcount
        except sqlite3.Error as e:
            print(f"执行SQL失败: {e}")
            raise
    
    def generate_session_id(self, username: str) -> str:
        """
        为用户生成新的session ID，有效期24小时
        
        Args:
            username: 用户名
            
        Returns:
            生成的session ID
        """
        try:
            # 生成32字节的随机session ID
            session_id = secrets.token_urlsafe(32)
            
            # 计算过期时间（24小时后）
            expires_at = datetime.datetime.now() + datetime.timedelta(hours=24)
            
            # 首先使旧的session失效
            self.invalidate_user_sessions(username)
            
            # 插入新的session记录
            session_data = {
                'session_id': session_id,
                'username': username,
                'expires_at': expires_at.isoformat(),
                'is_active': 1
            }
            
            self.insert('session_ID', session_data)
            
            return session_id
            
        except sqlite3.Error as e:
            logging.error(f"Generate session ID error: {e}")
            raise
    
    def validate_session(self, session_id: str) -> Optional[str]:
        """
        验证session ID是否有效
        
        Args:
            session_id: 要验证的session ID
            
        Returns:
            如果有效返回用户名，否则返回None
        """
        try:
            # 查询session记录
            sessions = self.select('session_ID', 
                                 'session_id = ? AND is_active = 1', 
                                 (session_id,))
            
            if not sessions:
                return None
            
            session = sessions[0]
            expires_at = datetime.datetime.fromisoformat(session['expires_at'])
            
            # 检查是否过期
            if datetime.datetime.now() > expires_at:
                # 如果过期，设置为无效
                self.update('session_ID', 
                           {'is_active': 0}, 
                           'session_id = ?', 
                           (session_id,))
                return None
            
            return session['username']
            
        except sqlite3.Error as e:
            logging.error(f"Validate session error: {e}")
            return None
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        使特定的session ID失效
        
        Args:
            session_id: 要失效的session ID
            
        Returns:
            操作是否成功
        """
        try:
            rows_affected = self.update('session_ID',
                                      {'is_active': 0},
                                      'session_id = ?',
                                      (session_id,))
            return rows_affected > 0
        except sqlite3.Error as e:
            logging.error(f"Invalidate session error: {e}")
            return False
    
    def invalidate_user_sessions(self, username: str) -> int:
        """
        使用户的所有session失效
        
        Args:
            username: 用户名
            
        Returns:
            失效的session数量
        """
        try:
            rows_affected = self.update('session_ID',
                                      {'is_active': 0},
                                      'username = ? AND is_active = 1',
                                      (username,))
            return rows_affected
        except sqlite3.Error as e:
            logging.error(f"Invalidate user sessions error: {e}")
            return 0
    
    def cleanup_expired_sessions(self) -> int:
        """
        清理过期的session记录
        
        Returns:
            清理的session数量
        """
        try:
            current_time = datetime.datetime.now().isoformat()
            rows_affected = self.update('session_ID',
                                      {'is_active': 0},
                                      'expires_at < ? AND is_active = 1',
                                      (current_time,))
            return rows_affected
        except sqlite3.Error as e:
            logging.error(f"Cleanup expired sessions error: {e}")
            return 0
    
    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.disconnect()


# 使用示例
def example_usage():
    """数据库使用示例"""
    db_path = "example.db"
    
    # 使用上下文管理器自动处理连接
    with DatabaseManager(db_path) as db:
        db.initialize()
        
if __name__ == "__main__":
    example_usage()