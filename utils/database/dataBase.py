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
                # 用户信息表
                self.create_table("user_data", 
                                """id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                username TEXT NOT NULL UNIQUE, 
                                nickname TEXT NOT NULL, 
                                age INTEGER,
                                gender TEXT CHECK(gender IN ('male', 'female', 'other')),
                                height INTEGER,
                                weight REAL,
                                education TEXT,
                                occupation TEXT,
                                hobbies TEXT,
                                bio TEXT,
                                location TEXT,
                                contact_info TEXT,
                                personal_info TEXT,
                                profile_complete INTEGER DEFAULT 0,
                                is_active INTEGER DEFAULT 1,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"""
                )
                
                # 账户数据表（原有）
                self.create_table("account_data",
                                  """id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                  username TEXT NOT NULL UNIQUE, 
                                  p TEXT NOT NULL, 
                                  g TEXT NOT NULL,
                                  q TEXT NOT NULL, 
                                  y TEXT NOT NULL, 
                                  compressed_credential TEXT NOT NULL,
                                  bits INTEGER DEFAULT 256,
                                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"""
                )
                
                # 会话管理表（原有）
                self.create_table("session_ID",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                session_id TEXT NOT NULL UNIQUE,
                                username TEXT NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                expires_at TIMESTAMP NOT NULL,
                                is_active INTEGER DEFAULT 1,
                                FOREIGN KEY (username) REFERENCES user_data(username)"""
                )
                
                # 匹配偏好表
                self.create_table("match_preferences",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL,
                                preferred_gender TEXT,
                                min_age INTEGER,
                                max_age INTEGER,
                                min_height INTEGER,
                                max_height INTEGER,
                                preferred_education TEXT,
                                preferred_location TEXT,
                                deal_breakers TEXT,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (username) REFERENCES user_data(username)"""
                )
                
                # 推送记录表
                self.create_table("push_records",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                from_user TEXT NOT NULL,
                                to_user TEXT NOT NULL,
                                push_date DATE NOT NULL,
                                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'rejected', 'expired')),
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                responded_at TIMESTAMP,
                                FOREIGN KEY (from_user) REFERENCES user_data(username),
                                FOREIGN KEY (to_user) REFERENCES user_data(username),
                                UNIQUE(from_user, to_user, push_date)"""
                )
                
                # 匹配结果表
                self.create_table("matches",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user1 TEXT NOT NULL,
                                user2 TEXT NOT NULL,
                                match_date DATE NOT NULL,
                                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'blocked')),
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (user1) REFERENCES user_data(username),
                                FOREIGN KEY (user2) REFERENCES user_data(username),
                                UNIQUE(user1, user2)"""
                )
                
                # 用户互动记录表
                self.create_table("user_interactions",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                from_user TEXT NOT NULL,
                                to_user TEXT NOT NULL,
                                interaction_type TEXT CHECK(interaction_type IN ('view', 'like', 'skip', 'block')),
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (from_user) REFERENCES user_data(username),
                                FOREIGN KEY (to_user) REFERENCES user_data(username)"""
                )
                
                # 系统统计表
                self.create_table("system_stats",
                                """id INTEGER PRIMARY KEY AUTOINCREMENT,
                                stat_name TEXT NOT NULL UNIQUE,
                                stat_value TEXT NOT NULL,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"""
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
                    'compressed_credential': '',
                    'bits': 512
                }
                
                # 检查root用户是否已存在
                existing_root = self.select('account_data', 'username = ?', ('root',))
                if not existing_root:
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
    
    # 匹配系统相关方法
    def set_match_preferences(self, username: str, preferences: dict) -> bool:
        """设置用户匹配偏好"""
        try:
            # 检查是否已存在偏好设置
            existing = self.select('match_preferences', 'username = ?', (username,))
            
            preferences['username'] = username
            preferences['updated_at'] = datetime.datetime.now().isoformat()
            
            if existing:
                # 更新现有偏好
                self.update('match_preferences', preferences, 'username = ?', (username,))
            else:
                # 创建新的偏好设置
                preferences['created_at'] = datetime.datetime.now().isoformat()
                self.insert('match_preferences', preferences)
            
            return True
        except sqlite3.Error as e:
            logging.error(f"Set match preferences error: {e}")
            return False
    
    def get_match_preferences(self, username: str) -> Optional[dict]:
        """获取用户匹配偏好"""
        try:
            prefs = self.select('match_preferences', 'username = ?', (username,))
            if prefs:
                return dict(prefs[0])
            return None
        except sqlite3.Error as e:
            logging.error(f"Get match preferences error: {e}")
            return None
    
    def get_potential_matches(self, username: str, limit: int = 10) -> List[dict]:
        """获取潜在匹配对象"""
        try:
            # 获取用户信息和偏好
            user_info = self.select('user_data', 'username = ?', (username,))
            if not user_info:
                return []
            
            user = dict(user_info[0])
            prefs = self.get_match_preferences(username)
            
            # 构建查询条件
            conditions = ["username != ?", "is_active = 1", "profile_complete = 1"]
            params = [username]
            
            # 根据偏好筛选
            if prefs:
                if prefs.get('preferred_gender'):
                    conditions.append("gender = ?")
                    params.append(prefs['preferred_gender'])
                
                if prefs.get('min_age'):
                    conditions.append("age >= ?")
                    params.append(prefs['min_age'])
                
                if prefs.get('max_age'):
                    conditions.append("age <= ?")
                    params.append(prefs['max_age'])
                
                if prefs.get('min_height'):
                    conditions.append("height >= ?")
                    params.append(prefs['min_height'])
                
                if prefs.get('max_height'):
                    conditions.append("height <= ?")
                    params.append(prefs['max_height'])
                
                if prefs.get('preferred_location'):
                    conditions.append("location = ?")
                    params.append(prefs['preferred_location'])
            
            # 排除已经推送过的用户（今天）
            today = datetime.date.today().isoformat()
            conditions.append("""username NOT IN (
                SELECT to_user FROM push_records 
                WHERE from_user = ? AND push_date = ?
            )""")
            params.extend([username, today])
            
            # 排除已经匹配的用户
            conditions.append("""username NOT IN (
                SELECT CASE 
                    WHEN user1 = ? THEN user2 
                    ELSE user1 
                END
                FROM matches 
                WHERE (user1 = ? OR user2 = ?) AND status = 'active'
            )""")
            params.extend([username, username, username])
            
            where_clause = " AND ".join(conditions)
            sql = f"SELECT * FROM user_data WHERE {where_clause} ORDER BY RANDOM() LIMIT ?"
            params.append(limit)
            
            matches = self.execute_custom_sql(sql, tuple(params))
            return [dict(match) for match in matches] if matches else []
            
        except sqlite3.Error as e:
            logging.error(f"Get potential matches error: {e}")
            return []
    
    def create_push_record(self, from_user: str, to_user: str) -> bool:
        """创建推送记录（双向）"""
        try:
            today = datetime.date.today().isoformat()
            
            # 创建双向推送记录
            push_data1 = {
                'from_user': from_user,
                'to_user': to_user,
                'push_date': today,
                'status': 'pending'
            }
            
            push_data2 = {
                'from_user': to_user,
                'to_user': from_user,
                'push_date': today,
                'status': 'pending'
            }
            
            self.insert('push_records', push_data1)
            self.insert('push_records', push_data2)
            
            return True
        except sqlite3.Error as e:
            logging.error(f"Create push record error: {e}")
            return False
    
    def get_pending_pushes(self, username: str) -> List[dict]:
        """获取用户待处理的推送"""
        try:
            # 获取待处理的推送
            pushes = self.select('push_records', 
                               'from_user = ? AND status = ?', 
                               (username, 'pending'))
            
            result = []
            for push in pushes:
                # 获取推送对象的详细信息
                user_info = self.select('user_data', 'username = ?', (push['to_user'],))
                if user_info:
                    user_data = dict(user_info[0])
                    # 不返回敏感信息
                    safe_user_data = {
                        'username': user_data['username'],
                        'nickname': user_data['nickname'],
                        'age': user_data['age'],
                        'gender': user_data['gender'],
                        'height': user_data['height'],
                        'education': user_data['education'],
                        'occupation': user_data['occupation'],
                        'hobbies': user_data['hobbies'],
                        'bio': user_data['bio'],
                        'location': user_data['location']
                    }
                    result.append({
                        'push_id': push['id'],
                        'user_info': safe_user_data,
                        'push_date': push['push_date']
                    })
            
            return result
        except sqlite3.Error as e:
            logging.error(f"Get pending pushes error: {e}")
            return []
    
    def respond_to_push(self, username: str, push_id: int, response: str) -> dict:
        """响应推送（接受/拒绝）"""
        try:
            # 获取推送记录
            push_records = self.execute_custom_sql(
                "SELECT * FROM push_records WHERE id = ? AND from_user = ?",
                (push_id, username)
            )
            
            if not push_records:
                return {'success': False, 'message': '推送记录不存在'}
            
            push = push_records[0]
            to_user = push['to_user']
            
            # 更新推送状态
            self.update('push_records', 
                       {'status': response, 'responded_at': datetime.datetime.now().isoformat()},
                       'id = ?', 
                       (push_id,))
            
            # 记录用户互动
            interaction_data = {
                'from_user': username,
                'to_user': to_user,
                'interaction_type': 'like' if response == 'accepted' else 'skip'
            }
            self.insert('user_interactions', interaction_data)
            
            # 检查是否双方都接受了
            if response == 'accepted':
                # 查看对方是否也接受了
                other_push = self.execute_custom_sql(
                    "SELECT * FROM push_records WHERE from_user = ? AND to_user = ? AND push_date = ?",
                    (to_user, username, push['push_date'])
                )
                
                if other_push and other_push[0]['status'] == 'accepted':
                    # 双方都接受，创建匹配
                    user1, user2 = sorted([username, to_user])  # 保证顺序一致
                    match_data = {
                        'user1': user1,
                        'user2': user2,
                        'match_date': datetime.date.today().isoformat(),
                        'status': 'active'
                    }
                    
                    try:
                        self.insert('matches', match_data)
                        return {'success': True, 'message': '匹配成功！', 'matched': True}
                    except sqlite3.IntegrityError:
                        # 匹配记录已存在
                        return {'success': True, 'message': '匹配成功！', 'matched': True}
                else:
                    return {'success': True, 'message': '已接受，等待对方回应', 'matched': False}
            else:
                return {'success': True, 'message': '已拒绝', 'matched': False}
                
        except sqlite3.Error as e:
            logging.error(f"Respond to push error: {e}")
            return {'success': False, 'message': f'操作失败: {str(e)}'}
    
    def get_user_matches(self, username: str) -> List[dict]:
        """获取用户的匹配列表"""
        try:
            matches = self.execute_custom_sql(
                """SELECT * FROM matches 
                   WHERE (user1 = ? OR user2 = ?) AND status = 'active'
                   ORDER BY created_at DESC""",
                (username, username)
            )
            
            result = []
            for match in matches:
                # 确定匹配的对方用户
                other_user = match['user2'] if match['user1'] == username else match['user1']
                
                # 获取对方用户信息
                user_info = self.select('user_data', 'username = ?', (other_user,))
                if user_info:
                    user_data = dict(user_info[0])
                    result.append({
                        'match_id': match['id'],
                        'matched_user': {
                            'username': user_data['username'],
                            'nickname': user_data['nickname'],
                            'age': user_data['age'],
                            'gender': user_data['gender'],
                            'bio': user_data['bio'],
                            'contact_info': user_data['contact_info']
                        },
                        'match_date': match['match_date']
                    })
            
            return result
        except sqlite3.Error as e:
            logging.error(f"Get user matches error: {e}")
            return []
    
    def check_profile_completeness(self, username: str) -> bool:
        """检查用户资料完整性"""
        try:
            user_info = self.select('user_data', 'username = ?', (username,))
            if not user_info:
                return False
            
            user = dict(user_info[0])
            required_fields = ['nickname', 'age', 'gender', 'bio']
            
            for field in required_fields:
                if not user.get(field):
                    return False
            
            return True
        except sqlite3.Error as e:
            logging.error(f"Check profile completeness error: {e}")
            return False
    
    def update_profile_completeness(self, username: str) -> bool:
        """更新用户资料完整性状态"""
        try:
            is_complete = self.check_profile_completeness(username)
            self.update('user_data', 
                       {'profile_complete': 1 if is_complete else 0,
                        'updated_at': datetime.datetime.now().isoformat()},
                       'username = ?', 
                       (username,))
            return is_complete
        except sqlite3.Error as e:
            logging.error(f"Update profile completeness error: {e}")
            return False

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