from flask import request, jsonify, g
import json
import logging
from ..database.dataBase import DatabaseManager
from ..fhe.fhe import SecureMatchingSystem, User, Platform

class FHEMatchingRoutes:
    def __init__(self, app, db_path, require_session):
        self.app = app
        self.db_path = db_path
        self.require_session = require_session
        
        # 初始化FHE系统
        self.fhe_system = None
        self.platform = None
        self._init_fhe_system()
        
        # 注册路由
        self._register_routes()
    
    def _init_fhe_system(self):
        """初始化FHE系统参数"""
        try:
            with DatabaseManager(self.db_path) as db:
                # 获取root用户的系统参数
                root_data = db.select('account_data', 'username = ?', ('root',))
                if root_data:
                    root = root_data[0]
                    p = int(root['p'])
                    g = int(root['g'])
                    q = int(root['q'])
                    
                    self.fhe_system = SecureMatchingSystem(bits=512)
                    self.fhe_system.setup_system(p, g, q)
                    self.platform = Platform(self.fhe_system)
                    
                    logging.info("FHE system initialized successfully")
                else:
                    # 如果没有root数据，创建新的系统参数
                    self.fhe_system = SecureMatchingSystem(bits=512)
                    p, g, q = self.fhe_system.setup_system(None, None, None)
                    self.platform = Platform(self.fhe_system)
                    
                    # 保存到数据库
                    root_data = {
                        'username': 'root',
                        'p': str(p),
                        'g': str(g),
                        'q': str(q),
                        'y': str(g),  # 临时值
                        'compressed_credential': '',
                        'bits': 512
                    }
                    db.insert('account_data', root_data)
                    
                    logging.info("FHE system created and saved")
                    
        except Exception as e:
            logging.error(f"Failed to initialize FHE system: {e}")
            raise
    
    def _register_routes(self):
        """注册所有FHE匹配相关路由"""
        
        @self.app.route('/api/fhe/init_user', methods=['POST'])
        @self.require_session
        def init_fhe_user():
            """初始化用户的FHE密钥对和联系方式加密"""
            try:
                username = g.username
                data = request.get_json()
                contact_info = data.get('contact_info', '')
                
                # 创建用户实例
                user = User(username, self.fhe_system, contact_info)
                
                # 生成DH密钥对
                dh_public_key = user.generate_dh_keypair()
                
                # 保存公钥到数据库
                with DatabaseManager(self.db_path) as db:
                    db.update('user_data', 
                             {'contact_info': contact_info}, 
                             'username = ?', 
                             (username,))
                    
                    # 检查是否已有密钥记录
                    existing = db.select('account_data', 'username = ?', (username,))
                    if existing:
                        db.update('account_data',
                                 {'y': str(dh_public_key)},
                                 'username = ?',
                                 (username,))
                    else:
                        # 使用系统参数创建用户记录
                        root_data = db.select('account_data', 'username = ?', ('root',))[0]
                        user_data = {
                            'username': username,
                            'p': root_data['p'],
                            'g': root_data['g'],
                            'q': root_data['q'],
                            'y': str(dh_public_key),
                            'compressed_credential': '',
                            'bits': 512
                        }
                        db.insert('account_data', user_data)
                
                return jsonify({
                    'success': True,
                    'message': 'FHE用户初始化成功',
                    'public_key': str(dh_public_key)
                })
                
            except Exception as e:
                logging.error(f"Init FHE user error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/fhe/send_match_request', methods=['POST'])
        @self.require_session
        def send_match_request():
            """发送同态加密匹配请求"""
            try:
                username = g.username
                data = request.get_json()
                target_username = data.get('target_username')
                choice = data.get('choice', True)  # True为接受，False为拒绝
                
                if not target_username:
                    return jsonify({'success': False, 'message': '目标用户名不能为空'}), 400
                
                with DatabaseManager(self.db_path) as db:
                    # 获取双方的密钥信息
                    requester_data = db.select('account_data', 'username = ?', (username,))[0]
                    target_data = db.select('account_data', 'username = ?', (target_username,))
                    
                    if not target_data:
                        return jsonify({'success': False, 'message': '目标用户不存在'}), 404
                    
                    target_data = target_data[0]
                    
                    # 获取联系方式
                    requester_user_info = db.select('user_data', 'username = ?', (username,))[0]
                    
                    # 创建用户实例
                    requester = User(username, self.fhe_system, requester_user_info['contact_info'])
                    requester.dh_private_key = 12345  # 这里应该从安全存储中获取
                    requester.dh_public_key = int(requester_data['y'])
                    
                    # 计算与目标用户的共享密钥
                    target_public_key = int(target_data['y'])
                    requester.compute_shared_secret(target_public_key)
                    
                    # 设置选择并加密
                    requester.set_choice(choice)
                    choice_cipher, _ = requester.encrypt_choice()
                    
                    # 准备联系方式
                    encrypted_contact, contact_key_cipher = requester.prepare_contact_info()
                    
                    # 保存匹配请求到数据库
                    request_data = {
                        'requester_id': username,
                        'target_id': target_username,
                        'requester_choice_cipher': json.dumps({
                            'c1': str(choice_cipher[0]),
                            'c2': str(choice_cipher[1])
                        }),
                        'requester_contact_data': json.dumps({
                            'encrypted_contact': encrypted_contact.hex(),
                            'contact_key_cipher': {
                                'c1': str(contact_key_cipher[0]),
                                'c2': str(contact_key_cipher[1])
                            }
                        }),
                        'status': 'pending'
                    }
                    
                    # 检查是否已存在该匹配请求
                    existing = db.execute_custom_sql(
                        "SELECT * FROM match_requests WHERE requester_id = ? AND target_id = ? AND status = 'pending'",
                        (username, target_username)
                    )
                    
                    if existing:
                        return jsonify({'success': False, 'message': '已存在待处理的匹配请求'}), 400
                    
                    request_id = db.insert('match_requests', request_data)
                    
                return jsonify({
                    'success': True,
                    'message': '匹配请求发送成功',
                    'request_id': request_id
                })
                
            except Exception as e:
                logging.error(f"Send match request error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/fhe/get_match_requests', methods=['GET'])
        @self.require_session
        def get_match_requests():
            """获取待处理的匹配请求"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    requests = db.execute_custom_sql(
                        """SELECT mr.*, u.nickname as requester_name 
                           FROM match_requests mr
                           JOIN user_data u ON mr.requester_id = u.username
                           WHERE mr.target_id = ? AND mr.status = 'pending'
                           ORDER BY mr.created_at DESC""",
                        (username,)
                    )
                    
                    result = []
                    for req in requests:
                        result.append({
                            'request_id': req['id'],
                            'requester_id': req['requester_id'],
                            'requester_name': req['requester_name'],
                            'created_at': req['created_at']
                        })
                    
                return jsonify({
                    'success': True,
                    'requests': result
                })
                
            except Exception as e:
                logging.error(f"Get match requests error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/fhe/respond_match_request', methods=['POST'])
        @self.require_session
        def respond_match_request():
            """响应匹配请求"""
            try:
                username = g.username
                data = request.get_json()
                request_id = data.get('request_id')
                choice = data.get('choice', True)
                
                with DatabaseManager(self.db_path) as db:
                    # 获取匹配请求
                    req_data = db.execute_custom_sql(
                        "SELECT * FROM match_requests WHERE id = ? AND target_id = ? AND status = 'pending'",
                        (request_id, username)
                    )
                    
                    if not req_data:
                        return jsonify({'success': False, 'message': '匹配请求不存在'}), 404
                    
                    req = req_data[0]
                    requester_id = req['requester_id']
                    
                    # 获取双方密钥信息
                    responder_data = db.select('account_data', 'username = ?', (username,))[0]
                    requester_data = db.select('account_data', 'username = ?', (requester_id,))[0]
                    
                    # 获取联系方式
                    responder_user_info = db.select('user_data', 'username = ?', (username,))[0]
                    
                    # 创建响应者实例
                    responder = User(username, self.fhe_system, responder_user_info['contact_info'])
                    responder.dh_private_key = 54321  # 这里应该从安全存储中获取
                    responder.dh_public_key = int(responder_data['y'])
                    
                    # 计算共享密钥
                    requester_public_key = int(requester_data['y'])
                    responder.compute_shared_secret(requester_public_key)
                    
                    # 设置选择并加密
                    responder.set_choice(choice)
                    responder_choice_cipher, _ = responder.encrypt_choice()
                    
                    # 准备联系方式
                    responder_encrypted_contact, responder_contact_key_cipher = responder.prepare_contact_info()
                    
                    # 解析请求者的数据
                    requester_choice_data = json.loads(req['requester_choice_cipher'])
                    requester_contact_data = json.loads(req['requester_contact_data'])
                    
                    requester_choice_cipher = (
                        int(requester_choice_data['c1']),
                        int(requester_choice_data['c2'])
                    )
                    
                    requester_encrypted_contact = bytes.fromhex(requester_contact_data['encrypted_contact'])
                    requester_contact_key_cipher = (
                        int(requester_contact_data['contact_key_cipher']['c1']),
                        int(requester_contact_data['contact_key_cipher']['c2'])
                    )
                    
                    # 平台处理匹配
                    user1_data = (requester_choice_cipher, (requester_encrypted_contact, requester_contact_key_cipher))
                    user2_data = (responder_choice_cipher, (responder_encrypted_contact, responder_contact_key_cipher))
                    
                    result_cipher, user1_gets_data, user2_gets_data = self.platform.process_secure_matching(
                        user1_data, user2_data
                    )
                    
                    # 保存匹配结果
                    match_result_data = {
                        'request_id': request_id,
                        'user1_id': requester_id,
                        'user2_id': username,
                        'result_cipher': json.dumps({
                            'c1': str(result_cipher[0]),
                            'c2': str(result_cipher[1])
                        }),
                        'user1_contact_data': json.dumps({
                            'contact_key_cipher': {
                                'c1': str(user1_gets_data[0][0]),
                                'c2': str(user1_gets_data[0][1])
                            },
                            'encrypted_contact': user1_gets_data[1].hex()
                        }),
                        'user2_contact_data': json.dumps({
                            'contact_key_cipher': {
                                'c1': str(user2_gets_data[0][0]),
                                'c2': str(user2_gets_data[0][1])
                            },
                            'encrypted_contact': user2_gets_data[1].hex()
                        })
                    }
                    
                    match_result_id = db.insert('match_results', match_result_data)
                    
                    # 更新请求状态
                    db.update('match_requests', {'status': 'processed'}, 'id = ?', (request_id,))
                    
                return jsonify({
                    'success': True,
                    'message': '匹配处理完成',
                    'match_result_id': match_result_id
                })
                
            except Exception as e:
                logging.error(f"Respond match request error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/fhe/get_match_results', methods=['GET'])
        @self.require_session
        def get_match_results():
            """获取用户的匹配结果"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    results = db.execute_custom_sql(
                        """SELECT mr.*, 
                                  u1.nickname as user1_name,
                                  u2.nickname as user2_name
                           FROM match_results mr
                           JOIN user_data u1 ON mr.user1_id = u1.username
                           JOIN user_data u2 ON mr.user2_id = u2.username
                           WHERE mr.user1_id = ? OR mr.user2_id = ?
                           ORDER BY mr.created_at DESC""",
                        (username, username)
                    )
                    
                    result_list = []
                    for result in results:
                        is_user1 = (result['user1_id'] == username)
                        other_user = result['user2_id'] if is_user1 else result['user1_id']
                        other_name = result['user2_name'] if is_user1 else result['user1_name']
                        
                        result_list.append({
                            'match_result_id': result['id'],
                            'other_user': other_user,
                            'other_name': other_name,
                            'created_at': result['created_at'],
                            'is_user1': is_user1
                        })
                    
                return jsonify({
                    'success': True,
                    'results': result_list
                })
                
            except Exception as e:
                logging.error(f"Get match results error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/fhe/decrypt_result', methods=['POST'])
        @self.require_session
        def decrypt_match_result():
            """解密匹配结果和联系方式"""
            try:
                username = g.username
                data = request.get_json()
                match_result_id = data.get('match_result_id')
                
                with DatabaseManager(self.db_path) as db:
                    # 获取匹配结果
                    result_data = db.execute_custom_sql(
                        "SELECT * FROM match_results WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
                        (match_result_id, username, username)
                    )
                    
                    if not result_data:
                        return jsonify({'success': False, 'message': '匹配结果不存在'}), 404
                    
                    result = result_data[0]
                    is_user1 = (result['user1_id'] == username)
                    other_user = result['user2_id'] if is_user1 else result['user1_id']
                    
                    # 获取用户密钥信息
                    user_data = db.select('account_data', 'username = ?', (username,))[0]
                    other_user_data = db.select('account_data', 'username = ?', (other_user,))[0]
                    user_info = db.select('user_data', 'username = ?', (username,))[0]
                    
                    # 创建用户实例
                    user = User(username, self.fhe_system, user_info['contact_info'])
                    user.dh_private_key = 12345 if is_user1 else 54321  # 应该从安全存储获取
                    user.dh_public_key = int(user_data['y'])
                    
                    # 计算共享密钥
                    other_public_key = int(other_user_data['y'])
                    user.compute_shared_secret(other_public_key)
                    
                    # 解析匹配结果
                    result_cipher_data = json.loads(result['result_cipher'])
                    result_cipher = (
                        int(result_cipher_data['c1']),
                        int(result_cipher_data['c2'])
                    )
                    
                    # 解密匹配结果
                    is_match, _ = user.decrypt_result(result_cipher)
                    
                    # 获取对方联系方式数据
                    if is_user1:
                        contact_data = json.loads(result['user1_contact_data'])
                    else:
                        contact_data = json.loads(result['user2_contact_data'])
                    
                    contact_key_cipher = (
                        int(contact_data['contact_key_cipher']['c1']),
                        int(contact_data['contact_key_cipher']['c2'])
                    )
                    encrypted_contact = bytes.fromhex(contact_data['encrypted_contact'])
                    
                    # 尝试解密联系方式
                    decrypted_contact = user.decrypt_contact_info(contact_key_cipher, encrypted_contact)
                    
                    # 记录解密结果
                    exchange_data = {
                        'match_result_id': match_result_id,
                        'user_id': username,
                        'decrypted_contact': decrypted_contact,
                        'exchange_success': decrypted_contact is not None
                    }
                    db.insert('contact_exchanges', exchange_data)
                    
                return jsonify({
                    'success': True,
                    'is_match': is_match,
                    'contact_info': decrypted_contact if is_match else None,
                    'message': '匹配成功，已获得联系方式' if is_match and decrypted_contact else 
                              '匹配失败或无法获得联系方式'
                })
                
            except Exception as e:
                logging.error(f"Decrypt match result error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500