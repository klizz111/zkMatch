import sqlite3
from typing import List, Tuple, Any, Optional
import logging

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
        # 创建用户表
        db.create_table("users", "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE, age INTEGER")
        
        # 插入数据
        user_data = {
            "name": "张三",
            "email": "zhangsan@example.com",
            "age": 25
        }
        user_id = db.insert("users", user_data)
        print(f"插入用户ID: {user_id}")
        
        # 查询所有用户
        users = db.select("users")
        print("所有用户:")
        for user in users:
            print(f"ID: {user['id']}, 姓名: {user['name']}, 邮箱: {user['email']}, 年龄: {user['age']}")
        
        # 根据条件查询
        young_users = db.select("users", "age < ?", (30,))
        print(f"年龄小于30的用户数量: {len(young_users)}")
        
        # 更新数据
        updated_rows = db.update("users", {"age": 26}, "name = ?", ("张三",))
        print(f"更新了 {updated_rows} 行数据")
        
        # 删除数据
        # deleted_rows = db.delete("users", "id = ?", (user_id,))
        # print(f"删除了 {deleted_rows} 行数据")

if __name__ == "__main__":
    example_usage()