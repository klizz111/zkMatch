from flask import request, jsonify, g
from ..matching import MatchingService, ProfileService
from ..database.dataBase import DatabaseManager
import datetime
import logging
from ..fhe.fhe import *
import random
from ..useful.gen_rand_message import generate_random_message_string
import json

class MatchingRoutes:
    """匹配系统相关的路由处理类"""
    
    def __init__(self, app, db_path: str, require_session_decorator):
        self.app = app
        self.db_path = db_path
        self.require_session = require_session_decorator
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
            
            db = self._get_db_manager()
            profile_service = ProfileService(db)
            result = profile_service.update_user_profile(username, data)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 404 if 'not found' in result['error'] else 400
                return jsonify(result), status_code
        
        @self.app.route('/api/profile_status', methods=['GET'])
        @self.require_session
        def get_profile_status():
            """获取用户资料完整性状态"""
            username = g.current_user
            db = self._get_db_manager()
            profile_service = ProfileService(db)
            result = profile_service.get_profile_status(username)
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 404
        
        @self.app.route('/api/match_preferences', methods=['GET', 'POST'])
        @self.require_session
        def match_preferences():
            """获取或设置匹配偏好"""
            username = g.current_user
            db = self._get_db_manager()
            profile_service = ProfileService(db)
            
            if request.method == 'GET':
                result = profile_service.get_match_preferences(username)
                return jsonify(result)
            
            elif request.method == 'POST':
                data = request.get_json()
                result = profile_service.set_match_preferences(username, data)
                
                if result['success']:
                    return jsonify(result)
                else:
                    return jsonify(result), 400
        
        @self.app.route('/api/daily_pushes', methods=['GET'])
        @self.require_session
        def get_daily_pushes():
            """获取今日推送"""
            username = g.current_user
            db = self._get_db_manager()
            matching_service = MatchingService(db)
            result = matching_service.get_daily_pushes(username)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 400 if 'Profile incomplete' in result['error'] else 500
                return jsonify(result), status_code
        
        @self.app.route('/api/generate_pushes', methods=['POST'])
        @self.require_session
        def generate_daily_pushes():
            """生成今日推送"""
            username = g.current_user
            db = self._get_db_manager()
            matching_service = MatchingService(db)
            result = matching_service.generate_daily_pushes(username)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 400 if 'Profile incomplete' in result['error'] else 500
                return jsonify(result), status_code
        
 
        @self.app.route('/api/respond_push', methods=['POST'])
        @self.require_session
        def respond_to_push():
            """响应推送（接受/拒绝）"""
            username = g.current_user
            data = request.get_json()
            
            push_id = data.get('push_id')
            encrypted_response_c1 = data.get('encrypted_response_c1')
            encrypted_response_c2 = data.get('encrypted_response_c2')
            encrypted_contact_info = data.get('encrypted_contact_info')
            encrypted_key_c1 = data.get('encrypted_key_c1')
            encrypted_key_c2 = data.get('encrypted_key_c2')
            
            if not push_id:
                return jsonify({'error': 'Invalid push_id'}), 400
            
            # 获取数据库管理器
            db = self._get_db_manager()
            
            try:
                # 获取推送记录信息
                push_records = db.execute_custom_sql(
                    "SELECT * FROM push_records WHERE id = ? AND from_user = ?",
                    (push_id, username)
                )
                
                if not push_records:
                    return jsonify({'error': '推送记录不存在'}), 404
                
                # 将status标记为accepted
                db.update('push_records', {'status': 'accepted'}, 'id = ?', (push_id,))
                
                push = push_records[0]
                to_user = push['to_user']
                
                # 获取系统公钥（root用户的公钥参数）
                root_account = db.select('account_data', 'username = ?', ('root',))
                if not root_account:
                    return jsonify({'error': '系统配置错误'}), 500
                
                bond_pub_key = {
                    'p': root_account[0]['p'],
                    'g': root_account[0]['g'],
                    'q': root_account[0]['q'],
                    'y': root_account[0]['y']
                }
                
                # 使用组合键查找现有的FHE记录
                existing_fhe = db.execute_custom_sql(
                    "SELECT * FROM fhe_records WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)",
                    (username, to_user, to_user, username)
                )
                
                if existing_fhe:
                    # 更新现有记录
                    fhe_record = existing_fhe[0]
                    
                    # 确定当前用户是username1还是username2
                    if fhe_record['username1'] == username:
                        # 当前用户是username1，更新用户1的数据
                        update_data = {
                            'visited_1': 1,
                            'encrypted_contact_info_1': str(encrypted_contact_info) if encrypted_contact_info else None,
                            'encrypted_enc_key_1_c1': encrypted_key_c1,
                            'encrypted_enc_key_1_c2': encrypted_key_c2,
                            'encrypted_choice_1_c1': encrypted_response_c1,
                            'encrypted_choice_1_c2': encrypted_response_c2,
                            'updated_at': datetime.datetime.now().isoformat()
                        }
                    else:
                        # 当前用户是username2，更新用户2的数据
                        update_data = {
                            'visited_2': 1,
                            'encrypted_contact_info_2': str(encrypted_contact_info) if encrypted_contact_info else None,
                            'encrypted_enc_key_2_c1': encrypted_key_c1,
                            'encrypted_enc_key_2_c2': encrypted_key_c2,
                            'encrypted_choice_2_c1': encrypted_response_c1,
                            'encrypted_choice_2_c2': encrypted_response_c2,
                            'updated_at': datetime.datetime.now().isoformat()
                        }
                    
                    db.update('fhe_records', update_data, 'id = ?', (fhe_record['id'],))
                    
                else:
                    # 创建新的fhe_records记录
                    # 确定用户顺序（按字母顺序排序以保持一致性）
                    users = sorted([username, to_user])
                    username1, username2 = users[0], users[1]
                    
                    fhe_data = {
                        'match_id': push_id,
                        'username1': username1,
                        'username2': username2,
                        'bond_pub_key': str(bond_pub_key),
                        'created_at': datetime.datetime.now().isoformat(),
                        'updated_at': datetime.datetime.now().isoformat()
                    }
                    
                    # 根据当前用户设置对应的字段
                    if username == username1:
                        fhe_data.update({
                            'visited_1': 1,
                            'encrypted_contact_info_1': str(encrypted_contact_info) if encrypted_contact_info else None,
                            'encrypted_enc_key_1_c1': encrypted_key_c1,
                            'encrypted_enc_key_1_c2': encrypted_key_c2,
                            'encrypted_choice_1_c1': encrypted_response_c1,
                            'encrypted_choice_1_c2': encrypted_response_c2,
                            'visited_2': 0
                        })
                    else:
                        fhe_data.update({
                            'visited_2': 1,
                            'encrypted_contact_info_2': str(encrypted_contact_info) if encrypted_contact_info else None,
                            'encrypted_enc_key_2_c1': encrypted_key_c1,
                            'encrypted_enc_key_2_c2': encrypted_key_c2,
                            'encrypted_choice_2_c1': encrypted_response_c1,
                            'encrypted_choice_2_c2': encrypted_response_c2,
                            'visited_1': 0
                        })
                    
                    db.insert('fhe_records', fhe_data)
                
                # 检查双方是否都已经响应
                updated_fhe = db.execute_custom_sql(
                    "SELECT * FROM fhe_records WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)",
                    (username, to_user, to_user, username)
                )
                
                if updated_fhe and updated_fhe[0]['visited_1'] == 1 and updated_fhe[0]['visited_2'] == 1:
                    # 双方都已响应，可以进行匹配计算    
                    system = SecureMatchingSystem()
                    system.setup_system(
                        int(bond_pub_key['p']),
                        int(bond_pub_key['g']),
                        int(bond_pub_key['q'])
                    )
                    
                    fhe_record = updated_fhe[0]
                    
                    # 获取双方的加密数据
                    user1_choice_cipher = (
                        int(fhe_record['encrypted_choice_1_c1']), 
                        int(fhe_record['encrypted_choice_1_c2'])
                    )
                    user1_contact_key_cipher = (
                        int(fhe_record['encrypted_enc_key_1_c1']), 
                        int(fhe_record['encrypted_enc_key_1_c2'])
                    )
                    
                    user2_choice_cipher = (
                        int(fhe_record['encrypted_choice_2_c1']), 
                        int(fhe_record['encrypted_choice_2_c2'])
                    )
                    user2_contact_key_cipher = (
                        int(fhe_record['encrypted_enc_key_2_c1']), 
                        int(fhe_record['encrypted_enc_key_2_c2'])
                    )
                    
                    # 同态运算
                    platform = Platform(system)
                    
                    # 准备用户数据
                    user1_data = (user1_choice_cipher, user1_contact_key_cipher)
                    user2_data = (user2_choice_cipher, user2_contact_key_cipher)
                    
                    # 执行安全匹配计算
                    final_result_cipher, contact2_key_for_user1, contact1_key_for_user2 = platform.process_secure_matching_v2(
                        user1_data, user2_data
                    )
                    
                    # 保存FHE计算结果
                    fhe_update = {
                        'fhe_caculated_choice_c1': str(final_result_cipher[0]),
                        'fhe_caculated_choice_c2': str(final_result_cipher[1]),
                        'fhe_caculated_enc_key_1_c1': str(contact1_key_for_user2[0]),
                        'fhe_caculated_enc_key_1_c2': str(contact1_key_for_user2[1]),
                        'fhe_caculated_enc_key_2_c1': str(contact2_key_for_user1[0]),
                        'fhe_caculated_enc_key_2_c2': str(contact2_key_for_user1[1]),
                        'updated_at': datetime.datetime.now().isoformat()
                    }
                    
                    db.update('fhe_records', fhe_update, 'id = ?', (fhe_record['id'],))
                    
                return jsonify({
                    'success': True,
                })
                                            
            except Exception as e:
                logging.error(f"Respond to push error: {e}")
                return jsonify({'error': f'操作失败: {str(e)}'}), 500
            
        
        @self.app.route('/api/my_matches', methods=['GET'])
        @self.require_session
        def get_my_matches():
            """获取我的匹配列表"""
            username = g.current_user
            db = self._get_db_manager()
            matching_service = MatchingService(db)
            result = matching_service.get_user_matches(username)
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 500
        
        @self.app.route('/api/stats', methods=['GET'])
        @self.require_session
        def get_user_stats():
            """获取用户统计信息"""
            username = g.current_user
            db = self._get_db_manager()
            matching_service = MatchingService(db)
            result = matching_service.get_user_stats(username)
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 500
            
        @self.app.route('/api/push_history', methods=['GET'])
        @self.require_session   
        def get_push_history():
            """获取推送历史记录"""
            username = g.current_user
            db = self._get_db_manager()
            
            # 查询条件：from_user为current_user/status为accepted
            push_records = db.execute_custom_sql(
                "SELECT * FROM push_records WHERE from_user = ? AND status = 'accepted' ORDER BY created_at DESC",
                (username,)
            )
            
            # push_records中获取to_user
            if not push_records:
                return jsonify({'error': '没有找到推送记录'}), 404
            
            uname_list = []
            for record in push_records:
                to_user = record['to_user']
                if to_user not in uname_list:
                    uname_list.append(to_user)
                    
            # 获取用户信息 - 修改为获取实际存在的字段
            user_profiles = db.execute_custom_sql(
                "SELECT username, nickname, age, gender, height, weight, education, hobbies, bio FROM user_data WHERE username IN ({})".format(
                    ','.join(['?'] * len(uname_list))
                ),
                tuple(uname_list)
            )
            
            # 构建用户信息映射
            user_info_map = {}
            for user in user_profiles:
                user_info_map[user['username']] = {
                    'username': user['username'],
                    'nickname': user['nickname'],
                    'age': user['age'],
                    'gender': user['gender'],
                    'height': user['height'],
                    'weight': user['weight'],
                    'education': user['education'],
                    'hobbies': user['hobbies'],
                    'bio': user['bio']
                }
            
            # 构建返回结果
            result = []
            for record in push_records:
                to_user = record['to_user']
                user_info = user_info_map.get(to_user, {})
                
                result.append({
                    'push_id': record['id'],
                    'to_user': to_user,
                    'status': record['status'],
                    'created_at': record['created_at'],
                    'user_info': user_info
                })
            return jsonify(result)
                
            
        @self.app.route('/api/fhe_match_results', methods=['POST'])
        @self.require_session
        def get_fhe_match_res():
            """获取fhe匹配结果"""
            username = g.current_user
            data = request.get_json()

            db = self._get_db_manager()
            itsusername = data.get('itsusername')
            
            try:
                # 在user_data中查询昵称对应的username
                if not itsusername:
                    return jsonify({'error': 'itsusername is required'}), 400
                
                to_user = db.execute_custom_sql(
                    "SELECT username FROM user_data WHERE nickname = ?",
                    (itsusername,)
                )
                                
                to_user = to_user[0]['username'] if to_user else None
                print("---------------------"+to_user+"---------------------"+username )

                if not to_user:
                    return jsonify({'error': 'Invalid itsusername'}), 400
                
                existing_fhe = db.execute_custom_sql(
                    "SELECT * FROM fhe_records WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)",
                    (username, to_user, to_user, username)
                )
                
                if existing_fhe:
                    fhe_record = existing_fhe[0]
                    
                    # 检查双方是否都已经响应
                    if fhe_record['visited_1'] == 1 and fhe_record['visited_2'] == 1:
                        # 双方都已经响应，返回FHE计算结果
                        username1 = fhe_record['username1']
                        
                        if username1 == username: # 当前用户是username1
                            contact_key = [fhe_record['fhe_caculated_enc_key_2_c1'], fhe_record['fhe_caculated_enc_key_2_c2']]
                            contact_info_str = fhe_record['encrypted_contact_info_2']
                        else: # 当前用户是username2
                            contact_key = [fhe_record['fhe_caculated_enc_key_1_c1'], fhe_record['fhe_caculated_enc_key_1_c2']]
                            contact_info_str = fhe_record['encrypted_contact_info_1']
                        
                        fhe_result = [fhe_record['fhe_caculated_choice_c1'], fhe_record['fhe_caculated_choice_c2']]
                        
                        # 处理contact_info格式
                        contact_info = contact_info_str
                        if contact_info_str and contact_info_str != 'None':
                            try:
                                # 尝试解析为JSON
                                import json
                                contact_info = json.loads(contact_info_str)
                            except:
                                # 如果解析失败，保持原始字符串
                                contact_info = contact_info_str
                    
                    else: 
                        # 如果没有完整的匹配数据，返回随机数据
                        contact_info = generate_random_message_string()
                        fhe_result = [str(random.getrandbits(512)), str(random.getrandbits(512))]
                        contact_key = [str(random.getrandbits(512)), str(random.getrandbits(512))]
                    
                    return jsonify({
                        'success': True,
                        'fhe_result': fhe_result,
                        'contact_key': contact_key,
                        'contact_info': contact_info
                    })
                else:
                    return jsonify({'error': '没有找到匹配的FHE记录'}), 404
                
            except Exception as e:
                logging.error(f"Get FHE match results error: {e}")
                return jsonify({'error': f'操作失败: {str(e)}'}), 500