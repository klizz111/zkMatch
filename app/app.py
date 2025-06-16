from flask import Flask, render_template, g
import sys
import os
import logging

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database.dataBase import DatabaseManager
from utils.api import AuthRoutes, MatchingRoutes

app = Flask(__name__)
app.config['DATABASE_PATH'] = 'datastorage.db'
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 在应用启动时进行初始化
_db_initialized = False

def init_database():
    """初始化数据库"""
    global _db_initialized
    if not _db_initialized:
        db_path = app.config['DATABASE_PATH']
        
        # 检查数据库文件是否存在
        if not os.path.exists(db_path):
            logging.info("数据库文件不存在，正在创建新数据库...")
            db = DatabaseManager(db_path)
            db.initialize()
        else:
            logging.info("数据库文件已存在，跳过初始化。")
        
        _db_initialized = True

def get_db():
    """获取数据库连接，如果不存在则创建"""
    if 'db' not in g:
        g.db = DatabaseManager(app.config['DATABASE_PATH'])
        g.db.connect()
    return g.db

def close_db(error):
    """关闭数据库连接"""
    db = g.pop('db', None)
    if db is not None:
        db.disconnect()

@app.teardown_appcontext
def close_db_on_teardown(error):
    close_db(error)

# 页面路由
@app.route('/')
def index():
    """登录页面"""
    return render_template('auth.html')

@app.route('/dashboard')
def dashboard():
    """匹配系统主页面"""
    return render_template('index.html')

# 初始化API路由
def init_api_routes():
    """初始化所有API路由"""
    db_path = app.config['DATABASE_PATH']
    
    # 初始化认证路由
    auth_routes = AuthRoutes(app, db_path)
    
    # 初始化匹配系统路由，传入认证装饰器
    matching_routes = MatchingRoutes(app, db_path, auth_routes.require_session)
    
    logging.info("API routes initialized successfully")

if __name__ == '__main__':
    # 应用启动时初始化
    init_database()
    init_api_routes()
    
    logging.info("Starting Flask application...")
    app.run(debug=True)
