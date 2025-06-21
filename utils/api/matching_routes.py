from flask import request, jsonify, g
from ..matching import MatchingService, ProfileService
from ..database.dataBase import DatabaseManager
import json
import logging
import random
from ..fhe.fhee import FHEMatchingDemo

class MatchingRoutes:
    """匹配系统相关的路由处理类"""
    
    def __init__(self, app, db_path: str, require_session_decorator):
        self.app = app
        self.db_path = db_path
        self.require_session = require_session_decorator
        self.fhe_demo = FHEMatchingDemo()
        self._register_routes()
    
    def _get_db_manager(self):
        """获取数据库管理器实例"""
        if 'db' not in g:
            g.db = DatabaseManager(self.db_path)
            g.db.connect()
        return g.db
    
    def _register_routes(self):
        """注册所有匹配系统相关的路由"""
        
        @self.app.route('/api/user_info', methods=['GET'])
        @self.require_session
        def get_user_info():
            """获取用户信息 - 需要有效的session"""
            username = g.current_user
            db = self._get_db_manager()
            profile_service = ProfileService(db)
            result = profile_service.get_user_profile(username)
            
            if result['success']:
                return jsonify(result['profile'])
            else:
                return jsonify({'error': result['error']}), 404
        
        @self.app.route('/api/update_profile', methods=['POST'])
        @self.require_session
        def update_profile():
            """更新用户资料 - 需要有效的session"""
            username = g.current_user
            data = request.get_json()
            
            # 注意：联系方式不存储到服务器
            profile_data = {k: v for k, v in data.items() if k != 'contact_info'}
            
            db = self._get_db_manager()
            profile_service = ProfileService(db)
            result = profile_service.update_profile(username, profile_data)
            
            if result['success']:
                return jsonify({'message': '资料更新成功'})
            else:
                return jsonify({'error': result['error']}), 400
        
        @self.app.route('/api/system_params', methods=['GET'])
        @self.require_session
        def get_system_params():
            """获取系统FHE参数"""
            try:
                with DatabaseManager(self.db_path) as db:
                    root_data = db.select('account_data', 'username = ?', ('root',))
                    if root_data:
                        params = {
                            'p': int(root_data[0]['p']),
                            'g': int(root_data[0]['g']),
                            'q': int(root_data[0]['q'])
                        }
                        return jsonify({'success': True, 'params': params})
                    else:
                        return jsonify({'success': False, 'message': '系统参数未初始化'})
            except Exception as e:
                logging.error(f"Get system params error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/daily_pushes', methods=['GET'])
        @self.require_session
        def get_daily_pushes():
            """获取每日推送"""
            username = g.current_user
            try:
                with DatabaseManager(self.db_path) as db:
                    # 获取用户公钥
                    user_data = db.select('account_data', 'username = ?', (username,))
                    if not user_data:
                        return jsonify({'error': '用户不存在'}), 404
                    
                    # 获取其他用户的资料作为推送
                    all_users = db.select('user_profiles', 'username != ?', (username,))
                    pushes = []
                    
                    for user in all_users:
                        # 获取用户的公钥
                        user_account = db.select('account_data', 'username = ?', (user['username'],))
                        if user_account:
                            push_data = {
                                'push_id': len(pushes) + 1,
                                'target_user': user['username'],
                                'profile': {
                                    'name': user.get('name', ''),
                                    'age': user.get('age', ''),
                                    'gender': user.get('gender', ''),
                                    'interests': user.get('interests', ''),
                                    'bio': user.get('bio', '')
                                },
                                'public_key': int(user_account[0]['public_key'])
                            }
                            pushes.append(push_data)
                    
                    return jsonify({'pushes': pushes})
            except Exception as e:
                logging.error(f"Get daily pushes error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/submit_choice', methods=['POST'])
        @self.require_session
        def submit_choice():
            """提交用户选择（加密的联系方式和选择）"""
            username = g.current_user
            data = request.get_json()
            
            try:
                target_user = data['target_user']
                encrypted_contact = data['encrypted_contact']
                encrypted_choice = data['encrypted_choice']
                
                with DatabaseManager(self.db_path) as db:
                    # 存储用户的选择
                    existing = db.select('fhe_choices', 
                                       'from_user = ? AND to_user = ?', 
                                       (username, target_user))
                    
                    if existing:
                        # 更新现有记录
                        db.update('fhe_choices',
                                'encrypted_contact = ?, encrypted_choice = ?, status = ?',
                                'from_user = ? AND to_user = ?',
                                (json.dumps(encrypted_contact), 
                                 json.dumps(encrypted_choice),
                                 'submitted',
                                 username, target_user))
                    else:
                        # 插入新记录
                        db.insert('fhe_choices', {
                            'from_user': username,
                            'to_user': target_user,
                            'encrypted_contact': json.dumps(encrypted_contact),
                            'encrypted_choice': json.dumps(encrypted_choice),
                            'status': 'submitted'
                        })
                    
                    # 检查是否双方都已提交
                    reverse_choice = db.select('fhe_choices',
                                             'from_user = ? AND to_user = ?',
                                             (target_user, username))
                    
                    if reverse_choice and reverse_choice[0]['status'] == 'submitted':
                        # 双方都已提交，执行同态运算
                        self._perform_homomorphic_computation(username, target_user, db)
                
                return jsonify({'success': True, 'message': '选择已提交'})
                
            except Exception as e:
                logging.error(f"Submit choice error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/matching_status', methods=['GET'])
        @self.require_session
        def get_matching_status():
            """获取匹配状态"""
            username = g.current_user
            target_user = request.args.get('target_user')
            
            try:
                with DatabaseManager(self.db_path) as db:
                    # 检查匹配结果
                    result = db.select('fhe_results',
                                     '(user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)',
                                     (username, target_user, target_user, username))
                    
                    if result:
                        # 返回真实的同态运算结果
                        result_data = result[0]
                        return jsonify({
                            'has_result': True,
                            'result_product': json.loads(result_data['result_product']),
                            'shared_key_encrypted': json.loads(result_data['shared_key_encrypted']),
                            'contact_a_encrypted': json.loads(result_data['contact_a_encrypted']),
                            'contact_b_encrypted': json.loads(result_data['contact_b_encrypted'])
                        })
                    else:
                        # 检查是否已提交选择
                        choice = db.select('fhe_choices',
                                         'from_user = ? AND to_user = ?',
                                         (username, target_user))
                        
                        if choice:
                            # 返回伪结果
                            fake_result = self._generate_fake_result(username, target_user, db)
                            return jsonify({
                                'has_result': True,
                                'is_fake': True,
                                **fake_result
                            })
                        else:
                            return jsonify({'has_result': False})
                            
            except Exception as e:
                logging.error(f"Get matching status error: {e}")
                return jsonify({'error': str(e)}), 500

    def _perform_homomorphic_computation(self, user1, user2, db):
        """执行同态运算"""
        try:
            # 获取双方的选择
            choice1 = db.select('fhe_choices', 'from_user = ? AND to_user = ?', (user1, user2))[0]
            choice2 = db.select('fhe_choices', 'from_user = ? AND to_user = ?', (user2, user1))[0]
            
            # 获取系统参数
            root_data = db.select('account_data', 'username = ?', ('root',))[0]
            p = int(root_data['p'])
            
            # 解析加密的选择
            enc_choice1 = json.loads(choice1['encrypted_choice'])
            enc_choice2 = json.loads(choice2['encrypted_choice'])
            
            # 执行同态乘法
            result_product = self.fhe_demo.homomorphic_multiply(enc_choice1, enc_choice2, p)
            
            # 生成共享密钥的加密形式
            shared_key_encrypted = self.fhe_demo.encrypt_shared_key(user1, user2, p)
            
            # 获取加密的联系方式
            contact_a = json.loads(choice1['encrypted_contact'])
            contact_b = json.loads(choice2['encrypted_contact'])
            
            # 存储结果
            db.insert('fhe_results', {
                'user1': user1,
                'user2': user2,
                'result_product': json.dumps(result_product),
                'shared_key_encrypted': json.dumps(shared_key_encrypted),
                'contact_a_encrypted': json.dumps(contact_a),
                'contact_b_encrypted': json.dumps(contact_b),
                'status': 'computed'
            })
            
            # 更新选择状态
            db.update('fhe_choices', 'status = ?', 'from_user = ? AND to_user = ?',
                     ('computed', user1, user2))
            db.update('fhe_choices', 'status = ?', 'from_user = ? AND to_user = ?',
                     ('computed', user2, user1))
                     
        except Exception as e:
            logging.error(f"Homomorphic computation error: {e}")

    def _generate_fake_result(self, user1, user2, db):
        """生成伪结果"""
        try:
            # 获取系统参数
            root_data = db.select('account_data', 'username = ?', ('root',))[0]
            p = int(root_data['p'])
            g = int(root_data['g'])
            
            # 生成随机数作为伔结果
            random_value = random.randint(1, p-1)
            fake_result = pow(g, random_value, p)
            
            return {
                'result_product': {'c1': fake_result, 'c2': fake_result},
                'shared_key_encrypted': {'c1': fake_result, 'c2': fake_result},
                'contact_a_encrypted': {'c1': fake_result, 'c2': fake_result},
                'contact_b_encrypted': {'c1': fake_result, 'c2': fake_result}
            }
        except Exception as e:
            logging.error(f"Generate fake result error: {e}")
            return {}