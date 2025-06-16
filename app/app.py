from flask import Flask, render_template, g, request, jsonify

import sys
import os
# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.database.dataBase import DatabaseManager
from utils.mathlib.elgamal import ElGamal
from utils.zk.dlogProof import dlogProof, dlogProofVerify
from utils.zk.crypto import compress_credential, generate_login_token, parse_login_token
import hashlib
import random
import logging

app = Flask(__name__)
app.config['DATABASE_PATH'] = 'datastorage.db'
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 在应用启动时进行一次性初始化
_db_initialized = False

def init_database():
    """一次性初始化数据库"""
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
    """用户注册API - 第一步：生成公钥参数"""
    try:
        data = request.get_json()
        username = data.get('username')
        seed_hash = data.get('seed_hash')
        bits = data.get('bits', 256)
        
        if not username or not seed_hash:
            return jsonify({'error': 'Username and seed_hash are required'}), 400
        
        db = get_db()
        
        # 检查用户名是否已存在
        existing_user = db.select('account_data', 'username = ?', (username,))
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 409
        
        # 生成ElGamal参数
        elgamal = ElGamal(bits)
        elgamal.keygen()
        
        p, g, y = elgamal.get_pkg()
        
        # 暂时保存到数据库（没有完整的公钥y，等客户端计算后更新）
        account_data = {
            'username': username,
            'p': str(p),
            'g': str(g),
            'q': str(elgamal.q),
            'y': '',  # 暂时为空，等待客户端计算
            'seed_hash': seed_hash,
            'compressed_credential': '',  # 暂时为空
            'bits': bits
        }
        
        db.insert('account_data', account_data)
        
        return jsonify({
            'success': True,
            'p': str(p),
            'g': str(g),
            'q': str(elgamal.q)
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
        
        user_data = user_record[0]
        p = user_data['p']
        g = user_data['g']
        
        # 生成压缩凭证（不包含私钥x，因为服务器不知道）
        login_token = generate_login_token(username, p, g, y)
        
        # 更新数据库
        update_data = {
            'y': str(y),
            'compressed_credential': login_token
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
            'login_token': login_token,
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
        login_token = data.get('login_token', '')
        
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        
        db = get_db()
        
        # 如果提供了登录令牌，使用令牌中的信息
        if login_token:
            try:
                token_data = parse_login_token(login_token)
                if token_data['username'] != username:
                    return jsonify({'error': 'Username mismatch with token'}), 400
                
                p = int(token_data['p'])
                g = int(token_data['g'])
                y = int(token_data['y'])
                
            except ValueError as e:
                return jsonify({'error': f'Invalid login token: {e}'}), 400
        else:
            # 从数据库获取用户信息
            user_record = db.select('account_data', 'username = ?', (username,))
            if not user_record:
                return jsonify({'error': 'User not found'}), 404
            
            user_data = user_record[0]
            p = int(user_data['p'])
            g = int(user_data['g'])
            y = int(user_data['y'])
        
        # 生成随机挑战
        challenge = random.randint(1, p-1)
        
        # 将挑战保存到session或临时存储（这里简化为返回给客户端）
        return jsonify({
            'success': True,
            'challenge': str(challenge),
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
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user_info': {
                    'username': username,
                    'login_token': user_data['compressed_credential']
                }
            })
        else:
            return jsonify({'error': 'Invalid proof'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user_info', methods=['GET'])
def get_user_info():
    """获取用户信息"""
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
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

if __name__ == '__main__':
    # 应用启动时初始化数据库
    init_database()
    app.run(debug=True)