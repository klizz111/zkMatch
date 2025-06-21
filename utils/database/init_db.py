from .dataBase import DatabaseManager
import logging

def init_database():
    """初始化数据库，创建所需的表"""
    db_path = 'data/matching_system.db'
    
    with DatabaseManager(db_path) as db:
        # 创建用户表
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建FHE选择表
        db.execute('''
            CREATE TABLE IF NOT EXISTS fhe_choices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                encrypted_contact TEXT NOT NULL,
                encrypted_choice TEXT NOT NULL,
                status TEXT DEFAULT 'submitted',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(from_user, to_user)
            )
        ''')
        
        # 创建FHE结果表
        db.execute('''
            CREATE TABLE IF NOT EXISTS fhe_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1 TEXT NOT NULL,
                user2 TEXT NOT NULL,
                result_product TEXT NOT NULL,
                shared_key_encrypted TEXT NOT NULL,
                contact_a_encrypted TEXT NOT NULL,
                contact_b_encrypted TEXT NOT NULL,
                status TEXT DEFAULT 'computed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user1, user2)
            )
        ''')
        
    logging.info("Database initialized successfully")