from flask import Flask, render_template, g, request, jsonify
from functools import wraps

import sys
import os
# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database.dataBase import DatabaseManager
from utils.mathlib.elgamal import ElGamal
from utils.zk.dlogProof import dlogProof, dlogProofVerify
from utils.zk.crypto_utils import compress_credential
import hashlib
import random
import logging

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

def require_session(f):
    """装饰器：要求有效的session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 从请求头获取session ID
        session_id = request.headers.get('Authorization')
        if session_id and session_id.startswith('Bearer '):
            session_id = session_id[7:]  # 移除 'Bearer ' 前缀
        else:
            # 也可以从请求参数获取
            session_id = request.args.get('session_id') or request.json.get('session_id') if request.json else None
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 401
        
        db = get_db()
        username = db.validate_session(session_id)
        
        if not username:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # 将用户名添加到g对象中，方便路由函数使用
        g.current_user = username
        return f(*args, **kwargs)
    
    return decorated_function
        
@app.teardown_appcontext
def close_db_on_teardown(error):
    close_db(error)

@app.route('/')
def index():
    return render_template('auth.html')

@app.route('/test')
def test():
    return render_template('elgamal_test.html')

@app.route('/about')
def about():
    return '<h1>About Page</h1>'

@app.route('/api/register', methods=['POST'])
def register():
    """用户注册API - 获取root用户的群参数"""
    try:
        data = request.get_json()
        username = data.get('username')
        seed_hash = data.get('seed_hash')
        
        if not username or not seed_hash:
            return jsonify({'error': 'Username and seed_hash are required'}), 400
        
        db = get_db()
        
        # 检查用户名是否已存在
        existing_user = db.select('account_data', 'username = ?', (username,))
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 409
        
        # 从root用户获取群参数
        root_record = db.select('account_data', 'username = ?', ('root',))
        if not root_record:
            return jsonify({'error': 'System not initialized - root user not found'}), 500
        
        root_data = root_record[0]
        p = root_data['p']
        g = root_data['g']
        q = root_data['q']
        
        # 创建用户记录（y将由客户端计算并在第二步发送）
        account_data = {
            'username': username,
            'p': p,
            'g': g,
            'q': q,
            'y': '',  # 暂时为空，等待客户端计算
            'seed_hash': seed_hash,
            'compressed_credential': '',  # 暂时为空
            'bits': 512  # 固定为512位
        }
        
        db.insert('account_data', account_data)
        
        return jsonify({
            'success': True,
            'p': p,
            'g': g,
            'q': q
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/complete_registration', methods=['POST'])
def complete_registration():
    """完成用户注册 - 第二步：客户端发送公钥"""
    try:
        data = request.get_json()
        username = data.get('username')
        y = data.get('y')
        
        if not username or not y:
            return jsonify({'error': 'Username and public key y are required'}), 400
        
        db = get_db()
        
        # 查找用户记录
        user_record = db.select('account_data', 'username = ?', (username,))
        if not user_record:
            return jsonify({'error': 'User not found'}), 404
        
        # 更新数据库
        update_data = {
            'y': str(y),
            'compressed_credential': ''  # 不再生成压缩凭证
        }
        
        db.update('account_data', update_data, 'username = ?', (username,))
        
        # 同时在用户表中创建记录
        user_data = {
            'username': username,
            'nickname': username,  # 默认昵称为用户名
            'age': None,
            'contact_info': None,
            'personal_info': None
        }
        
        try:
            db.insert('user_data', user_data)
        except:
            pass  # 如果已存在则忽略
        
        return jsonify({
            'success': True,
            'message': 'Registration completed successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login_challenge', methods=['POST'])
def login_challenge():
    """零知识登录 - 第一步：获取登录挑战"""
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        
        db = get_db()
        
        # 从数据库获取用户信息
        user_record = db.select('account_data', 'username = ?', (username,))
        if not user_record:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = user_record[0]
        p = int(user_data['p'])
        g = int(user_data['g'])
        y = int(user_data['y'])
        
        return jsonify({
            'success': True,
            'p': str(p),
            'g': str(g),
            'y': str(y)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login_verify', methods=['POST'])
def login_verify():
    """零知识登录 - 第二步：验证零知识证明"""
    try:
        data = request.get_json()
        username = data.get('username')
        proof_c = int(data.get('proof_c'))
        proof_z = int(data.get('proof_z'))
        
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        
        db = get_db()
        
        # 获取用户信息
        user_record = db.select('account_data', 'username = ?', (username,))
        if not user_record:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = user_record[0]
        p = int(user_data['p'])
        g = int(user_data['g'])
        y = int(user_data['y'])
        
        # 验证零知识证明
        proof = (proof_c, proof_z)
        is_valid = dlogProofVerify(y, g, p, proof)
        
        if is_valid:
            # 登录成功，生成session ID
            session_id = db.generate_session_id(username)
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'session_id': session_id,
                'user_info': {
                    'username': username
                }
            })
        else:
            return jsonify({'error': 'Invalid proof'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user_info', methods=['GET'])
@require_session
def get_user_info():
    """获取用户信息 - 需要有效的session"""
    # 从装饰器获取当前用户名
    username = g.current_user
    
    db = get_db()
    user_record = db.select('user_data', 'username = ?', (username,))
    
    if not user_record:
        return jsonify({'error': 'User not found'}), 404
    
    user = user_record[0]
    return jsonify({
        'username': user['username'],
        'nickname': user['nickname'],
        'age': user['age'],
        'contact_info': user['contact_info'],
        'personal_info': user['personal_info']
    })

@app.route('/api/update_profile', methods=['POST'])
@require_session
def update_profile():
    """更新用户资料 - 需要有效的session"""
    try:
        data = request.get_json()
        username = g.current_user
        
        # 允许更新的字段
        allowed_fields = ['nickname', 'age', 'contact_info', 'personal_info']
        update_data = {}
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        if not update_data:
            return jsonify({'error': 'No valid fields to update'}), 400
        
        db = get_db()
        rows_affected = db.update('user_data', update_data, 'username = ?', (username,))
        
        if rows_affected > 0:
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
@require_session
def logout():
    """用户登出 - 使session失效"""
    try:
        # 从请求头获取session ID
        session_id = request.headers.get('Authorization')
        if session_id and session_id.startswith('Bearer '):
            session_id = session_id[7:]
        else:
            session_id = request.args.get('session_id') or request.json.get('session_id') if request.json else None
        
        if session_id:
            db = get_db()
            success = db.invalidate_session(session_id)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Logged out successfully'
                })
            else:
                return jsonify({'error': 'Failed to logout'}), 500
        else:
            return jsonify({'error': 'Session ID not found'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate_session', methods=['GET'])
def validate_session():
    """验证session是否有效"""
    try:
        session_id = request.headers.get('Authorization')
        if session_id and session_id.startswith('Bearer '):
            session_id = session_id[7:]
        else:
            session_id = request.args.get('session_id')
        
        if not session_id:
            return jsonify({'valid': False, 'error': 'Session ID required'}), 400
        
        db = get_db()
        username = db.validate_session(session_id)
        
        if username:
            return jsonify({
                'valid': True,
                'username': username
            })
        else:
            return jsonify({'valid': False})
            
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500

if __name__ == '__main__':
    # 应用启动时初始化数据库
    init_database()
    app.run(debug=True)