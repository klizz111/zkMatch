from flask import request, jsonify, g
import logging
import datetime
import secrets
from ..database_manager import DatabaseManager

class MatchingAPI:
    def __init__(self, app, db_path):
        self.app = app
        self.db_path = db_path
        self._register_routes()

    def _register_routes(self):
        @self.app.route('/api/matching/respond_push', methods=['POST'])
        @self.require_session
        def respond_push():
            """响应推送请求，支持安全匹配"""
            try:
                username = g.username
                data = request.get_json()
                push_id = data.get('push_id')
                response = data.get('response')  # 'accepted' or 'rejected'
                use_secure_matching = data.get('secure_matching', False)
                
                if not push_id or not response:
                    return jsonify({'success': False, 'message': '参数不完整'}), 400
                
                with DatabaseManager(self.db_path) as db:
                    # 获取推送记录
                    push_records = db.execute_custom_sql(
                        "SELECT * FROM push_records WHERE id = ? AND from_user = ?",
                        (push_id, username)
                    )
                    
                    if not push_records:
                        return jsonify({'success': False, 'message': '推送记录不存在'}), 404
                    
                    push = push_records[0]
                    to_user = push['to_user']
                    
                    if use_secure_matching and response == 'accepted':
                        # 启用安全匹配模式
                        return self._handle_secure_matching_response(db, username, to_user, push_id, push)
                    else:
                        # 传统匹配模式
                        return self._handle_traditional_matching_response(db, username, push_id, response)
                        
            except Exception as e:
                logging.error(f"Respond push error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        def _handle_secure_matching_response(self, db, username, to_user, push_id, push):
            """处理安全匹配响应"""
            try:
                # 生成或获取匹配会话
                session_key = self._get_or_create_match_session(db, username, to_user)
                
                # 更新推送记录
                db.update('push_records', 
                         {'status': 'accepted', 
                          'responded_at': datetime.datetime.now().isoformat(),
                          'fhe_session_key': session_key},
                         'id = ?', (push_id,))
                
                # 获取用户联系方式
                user_info = db.select('user_data', 'username = ?', (username,))[0]
                contact_info = user_info['contact_info'] or f"{username}@secure.local"
                
                # 初始化用户的FHE参数
                self._init_user_fhe_params(db, username, contact_info)
                
                # 设置用户选择并加密
                success = self._set_secure_choice(db, session_key, username, True, contact_info)
                
                if success:
                    # 检查是否可以计算结果
                    self._try_compute_match_result(db, session_key)
                    
                    return jsonify({
                        'success': True, 
                        'message': '安全匹配请求已提交，等待对方响应',
                        'secure_matching': True,
                        'session_key': session_key
                    })
                else:
                    return jsonify({'success': False, 'message': '安全匹配初始化失败'}), 500
                    
            except Exception as e:
                logging.error(f"Secure matching response error: {e}")
                return jsonify({'success': False, 'message': '安全匹配处理失败'}), 500

        def _handle_traditional_matching_response(self, db, username, push_id, response):
            """处理传统匹配响应"""
            # 原有的匹配逻辑
            result = db.respond_to_push(username, push_id, response)
            return jsonify(result)

        def _get_or_create_match_session(self, db, user1, user2):
            """获取或创建匹配会话"""
            # 确保用户顺序一致
            if user1 > user2:
                user1, user2 = user2, user1
                
            # 检查是否已存在会话
            existing = db.select('fhe_match_sessions', 'user1_id = ? AND user2_id = ?', (user1, user2))
            
            if existing:
                return existing[0]['session_key']
            
            # 创建新会话
            session_key = secrets.token_urlsafe(32)
            session_data = {
                'session_key': session_key,
                'user1_id': user1,
                'user2_id': user2,
                'created_at': datetime.datetime.now().isoformat()
            }
            
            db.insert('fhe_match_sessions', session_data)
            return session_key

        def _init_user_fhe_params(self, db, username, contact_info):
            """初始化用户FHE参数"""
            try:
                # 获取系统参数
                root_data = db.select('account_data', 'username = ?', ('root',))[0]
                
                # 检查用户是否已有FHE参数
                existing = db.select('account_data', 'username = ?', (username,))
                
                if not existing:
                    # 创建用户FHE参数
                    from ..fhe.fhe import SecureMatchingSystem, User
                    
                    system = SecureMatchingSystem(bits=512)
                    system.setup_system(int(root_data['p']), int(root_data['g']), int(root_data['q']))
                    
                    user = User(username, system, contact_info)
                    dh_public_key = user.generate_dh_keypair()
                    
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
                
                # 更新联系方式
                db.update('user_data', {'contact_info': contact_info}, 'username = ?', (username,))
                
                return True
            except Exception as e:
                logging.error(f"Init user FHE params error: {e}")
                return False

        def _set_secure_choice(self, db, session_key, username, choice, contact_info):
            """设置用户的安全选择"""
            try:
                from ..fhe.fhe import SecureMatchingSystem, User
                import json
                
                # 获取会话信息
                session = db.select('fhe_match_sessions', 'session_key = ?', (session_key,))[0]
                
                # 确定用户是user1还是user2
                is_user1 = (session['user1_id'] == username)
                other_user = session['user2_id'] if is_user1 else session['user1_id']
                
                # 获取系统参数
                root_data = db.select('account_data', 'username = ?', ('root',))[0]
                system = SecureMatchingSystem(bits=512)
                system.setup_system(int(root_data['p']), int(root_data['g']), int(root_data['q']))
                
                # 创建用户实例
                user = User(username, system, contact_info)
                user_account = db.select('account_data', 'username = ?', (username,))[0]
                user.dh_public_key = int(user_account['y'])
                
                # 生成临时私钥（实际应用中应该安全存储）
                user.dh_private_key = 12345 if is_user1 else 54321
                
                # 获取对方公钥并计算共享密钥
                other_account = db.select('account_data', 'username = ?', (other_user,))
                if other_account:
                    other_public_key = int(other_account[0]['y'])
                    user.compute_shared_secret(other_public_key)
                else:
                    # 对方还没有初始化，使用虚拟值
                    user.compute_shared_secret(int(root_data['g']))
                
                # 设置选择并加密
                user.set_choice(choice)
                choice_cipher, _ = user.encrypt_choice()
                
                # 准备联系方式
                encrypted_contact, contact_key_cipher = user.prepare_contact_info()
                
                # 序列化数据
                choice_data = json.dumps({
                    'c1': str(choice_cipher[0]),
                    'c2': str(choice_cipher[1])
                })
                
                contact_data = json.dumps({
                    'encrypted_contact': encrypted_contact.hex(),
                    'contact_key_cipher': {
                        'c1': str(contact_key_cipher[0]),
                        'c2': str(contact_key_cipher[1])
                    }
                })
                
                # 更新会话数据
                if is_user1:
                    update_data = {
                        'user1_choice_cipher': choice_data,
                        'user1_contact_data': contact_data,
                        'user1_responded': 1
                    }
                else:
                    update_data = {
                        'user2_choice_cipher': choice_data,
                        'user2_contact_data': contact_data,
                        'user2_responded': 1
                    }
                
                db.update('fhe_match_sessions', update_data, 'session_key = ?', (session_key,))
                
                return True
                
            except Exception as e:
                logging.error(f"Set secure choice error: {e}")
                return False

        def _try_compute_match_result(self, db, session_key):
            """尝试计算匹配结果"""
            try:
                session = db.select('fhe_match_sessions', 'session_key = ?', (session_key,))[0]
                
                # 检查双方是否都已响应
                if not (session['user1_responded'] and session['user2_responded']):
                    return False
                
                # 检查是否已计算过结果
                if session['result_computed']:
                    return True
                
                from ..fhe.fhe import SecureMatchingSystem, Platform
                import json
                
                # 获取系统参数
                root_data = db.select('account_data', 'username = ?', ('root',))[0]
                system = SecureMatchingSystem(bits=512)
                system.setup_system(int(root_data['p']), int(root_data['g']), int(root_data['q']))
                
                platform = Platform(system)
                
                # 解析双方数据
                user1_choice_data = json.loads(session['user1_choice_cipher'])
                user2_choice_data = json.loads(session['user2_choice_cipher'])
                user1_contact_data = json.loads(session['user1_contact_data'])
                user2_contact_data = json.loads(session['user2_contact_data'])
                
                user1_choice_cipher = (
                    int(user1_choice_data['c1']),
                    int(user1_choice_data['c2'])
                )
                user2_choice_cipher = (
                    int(user2_choice_data['c1']),
                    int(user2_choice_data['c2'])
                )
                
                user1_encrypted_contact = bytes.fromhex(user1_contact_data['encrypted_contact'])
                user1_contact_key_cipher = (
                    int(user1_contact_data['contact_key_cipher']['c1']),
                    int(user1_contact_data['contact_key_cipher']['c2'])
                )
                
                user2_encrypted_contact = bytes.fromhex(user2_contact_data['encrypted_contact'])
                user2_contact_key_cipher = (
                    int(user2_contact_data['contact_key_cipher']['c1']),
                    int(user2_contact_data['contact_key_cipher']['c2'])
                )
                
                # 执行同态计算
                user1_data = (user1_choice_cipher, (user1_encrypted_contact, user1_contact_key_cipher))
                user2_data = (user2_choice_cipher, (user2_encrypted_contact, user2_contact_key_cipher))
                
                result_cipher, user1_gets_data, user2_gets_data = platform.process_secure_matching(
                    user1_data, user2_data
                )
                
                # 保存结果
                result_data = json.dumps({
                    'c1': str(result_cipher[0]),
                    'c2': str(result_cipher[1]),
                    'user1_contact_data': {
                        'contact_key_cipher': {
                            'c1': str(user1_gets_data[0][0]),
                            'c2': str(user1_gets_data[0][1])
                        },
                        'encrypted_contact': user1_gets_data[1].hex()
                    },
                    'user2_contact_data': {
                        'contact_key_cipher': {
                            'c1': str(user2_gets_data[0][0]),
                            'c2': str(user2_gets_data[0][1])
                        },
                        'encrypted_contact': user2_gets_data[1].hex()
                    }
                })
                
                db.update('fhe_match_sessions', 
                         {'result_cipher': result_data, 'result_computed': 1},
                         'session_key = ?', (session_key,))
                
                return True
                
            except Exception as e:
                logging.error(f"Compute match result error: {e}")
                return False

        @self.app.route('/api/matching/check_secure_results', methods=['GET'])
        @self.require_session
        def check_secure_results():
            """检查安全匹配结果"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    # 获取用户参与的匹配会话
                    sessions = db.execute_custom_sql(
                        """SELECT * FROM fhe_match_sessions 
                           WHERE (user1_id = ? OR user2_id = ?) AND result_computed = 1
                           ORDER BY created_at DESC""",
                        (username, username)
                    )
                    
                    results = []
                    for session in sessions:
                        other_user = session['user2_id'] if session['user1_id'] == username else session['user1_id']
                        
                        # 获取对方信息
                        other_info = db.select('user_data', 'username = ?', (other_user,))[0]
                        
                        results.append({
                            'session_key': session['session_key'],
                            'other_user': other_user,
                            'other_nickname': other_info['nickname'],
                            'created_at': session['created_at'],
                            'can_decrypt': True
                        })
                    
                    return jsonify({'success': True, 'results': results})
                    
            except Exception as e:
                logging.error(f"Check secure results error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/matching/decrypt_secure_result', methods=['POST'])
        @self.require_session
        def decrypt_secure_result():
            """解密安全匹配结果"""
            try:
                username = g.username
                data = request.get_json()
                session_key = data.get('session_key')
                
                if not session_key:
                    return jsonify({'success': False, 'message': '会话密钥不能为空'}), 400
                
                with DatabaseManager(self.db_path) as db:
                    # 获取会话信息
                    session = db.select('fhe_match_sessions', 'session_key = ?', (session_key,))
                    if not session:
                        return jsonify({'success': False, 'message': '会话不存在'}), 404
                    
                    session = session[0]
                    
                    # 检查用户是否参与此会话
                    if username not in [session['user1_id'], session['user2_id']]:
                        return jsonify({'success': False, 'message': '无权访问此会话'}), 403
                    
                    # 检查是否已解密过
                    existing_result = db.select('secure_match_results', 
                                              'session_key = ? AND user_id = ?', 
                                              (session_key, username))
                    
                    if existing_result:
                        result = existing_result[0]
                        return jsonify({
                            'success': True,
                            'is_match': bool(result['is_match']),
                            'contact_info': result['contact_info'],
                            'message': '匹配成功，已获得联系方式' if result['is_match'] and result['contact_info'] else '匹配失败'
                        })
                    
                    # 执行解密
                    decrypted_result = self._decrypt_match_result(db, session_key, username)
                    
                    return jsonify(decrypted_result)
                    
            except Exception as e:
                logging.error(f"Decrypt secure result error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        def _decrypt_match_result(self, db, session_key, username):
            """解密匹配结果"""
            try:
                from ..fhe.fhe import SecureMatchingSystem, User
                import json
                
                session = db.select('fhe_match_sessions', 'session_key = ?', (session_key,))[0]
                
                # 确定用户角色
                is_user1 = (session['user1_id'] == username)
                other_user = session['user2_id'] if is_user1 else session['user1_id']
                
                # 获取系统参数
                root_data = db.select('account_data', 'username = ?', ('root',))[0]
                system = SecureMatchingSystem(bits=512)
                system.setup_system(int(root_data['p']), int(root_data['g']), int(root_data['q']))
                
                # 获取用户信息
                user_info = db.select('user_data', 'username = ?', (username,))[0]
                user_account = db.select('account_data', 'username = ?', (username,))[0]
                other_account = db.select('account_data', 'username = ?', (other_user,))[0]
                
                # 创建用户实例
                user = User(username, system, user_info['contact_info'])
                user.dh_private_key = 12345 if is_user1 else 54321
                user.dh_public_key = int(user_account['y'])
                
                # 计算共享密钥
                other_public_key = int(other_account['y'])
                user.compute_shared_secret(other_public_key)
                
                # 解析结果数据
                result_data = json.loads(session['result_cipher'])
                result_cipher = (int(result_data['c1']), int(result_data['c2']))
                
                # 解密匹配结果
                is_match, _ = user.decrypt_result(result_cipher)
                
                contact_info = None
                if is_match:
                    # 获取对方联系方式数据
                    if is_user1:
                        contact_data = result_data['user1_contact_data']
                    else:
                        contact_data = result_data['user2_contact_data']
                    
                    contact_key_cipher = (
                        int(contact_data['contact_key_cipher']['c1']),
                        int(contact_data['contact_key_cipher']['c2'])
                    )
                    encrypted_contact = bytes.fromhex(contact_data['encrypted_contact'])
                    
                    # 解密联系方式
                    contact_info = user.decrypt_contact_info(contact_key_cipher, encrypted_contact)
                
                # 保存解密结果
                result_record = {
                    'session_key': session_key,
                    'user_id': username,
                    'is_match': is_match,
                    'contact_info': contact_info
                }
                db.insert('secure_match_results', result_record)
                
                return {
                    'success': True,
                    'is_match': is_match,
                    'contact_info': contact_info,
                    'message': '匹配成功，已获得联系方式' if is_match and contact_info else '匹配失败'
                }
                
            except Exception as e:
                logging.error(f"Decrypt match result error: {e}")
                return {'success': False, 'message': '解密失败'}

        # ...existing code...