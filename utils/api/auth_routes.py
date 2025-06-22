from flask import request, jsonify, g
from functools import wraps
from ..auth import AuthService, SessionManager
from ..database.dataBase import DatabaseManager
import datetime
import logging

class AuthRoutes:
    """认证相关的路由处理类"""
    
    def __init__(self, app, db_path: str):
        self.app = app
        self.db_path = db_path
        self._register_routes()
    
    def _get_db_manager(self):
        """获取数据库管理器实例"""
        if 'db' not in g:
            g.db = DatabaseManager(self.db_path)
            g.db.connect()
        return g.db
    
    def require_session(self, f):
        """装饰器：要求有效的session"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 从请求头获取session ID
            session_id = request.headers.get('Authorization')
            if session_id and session_id.startswith('Bearer '):
                session_id = session_id[7:]  # 移除 'Bearer ' 前缀
            else:
                # 也可以从请求参数获取
                session_id = request.args.get('session_id') or (request.json.get('session_id') if request.json else None)
            
            if not session_id:
                return jsonify({'success': False, 'message': 'Session ID required'}), 401
            
            db = self._get_db_manager()
            session_manager = SessionManager(db)
            username = session_manager.validate_session(session_id)
            
            if not username:
                return jsonify({'success': False, 'message': 'Invalid or expired session'}), 401
            
            # 将用户信息存储在g中供路由函数使用
            g.username = username
            g.session_id = session_id
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    def _register_routes(self):
        """注册所有认证相关的路由"""
        
        @self.app.route('/api/register', methods=['POST'])
        def register():
            """用户注册API - 第一步：获取群参数"""
            data = request.get_json()
            username = data.get('username')
            
            if not username:
                return jsonify({'success': False, 'message': '用户名不能为空'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.register_user_step1(username)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 409 if 'already exists' in result['error'] else 500
                return jsonify({'success': False, 'message': result['error']}), status_code
        
        @self.app.route('/api/complete_registration', methods=['POST'])
        def complete_registration():
            """完成用户注册 - 第二步：客户端发送公钥"""
            data = request.get_json()
            username = data.get('username')
            y = data.get('y')
            
            if not username or not y:
                return jsonify({'success': False, 'message': '用户名和公钥不能为空'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.register_user_step2(username, y)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 404 if 'not found' in result['error'] else 500
                return jsonify({'success': False, 'message': result['error']}), status_code
        
        @self.app.route('/api/login_challenge', methods=['POST'])
        def login():
            """登录 - 第一步：获取pgy"""
            data = request.get_json()
            username = data.get('username')
            
            if not username:
                return jsonify({'success': False, 'message': '用户名不能为空'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.get_login_challenge(username)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 404 if 'not found' in result['error'] else 500
                return jsonify({'success': False, 'message': result['error']}), status_code
        
        @self.app.route('/api/login_verify', methods=['POST'])
        def login_verify():
            """登录 - 第二步：验证零知识证明"""
            data = request.get_json()
            username = data.get('username')
            
            try:
                proof_c = int(data.get('proof_c'))
                proof_z = int(data.get('proof_z'))
            except (TypeError, ValueError):
                return jsonify({'success': False, 'message': '无效的证明格式'}), 400
            
            if not username:
                return jsonify({'success': False, 'message': '用户名不能为空'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.verify_login_proof(username, proof_c, proof_z)
            
            if result['success']:
                # 验证成功后创建session（只创建一次）
                try:
                    session_id = db.generate_session_id(username)
                    
                    # 获取用户信息
                    user = db.select('account_data', 'username = ?', (username,))[0]
                    
                    return {
                        'success': True,
                        'message': '登录成功',
                        'sessionId': session_id,
                        'userId': user['id'],
                        'username': user['username']
                    }
                    
                except Exception as e:
                    logging.error(f"Create session error: {e}")
                    return jsonify({'success': False, 'message': '创建会话失败'}), 500
            else:
                status_code = 401 if 'Invalid proof' in result['error'] else 500
                return jsonify({'success': False, 'message': result['error']}), status_code
        
        @self.app.route('/api/logout', methods=['POST'])
        @self.require_session
        def logout():
            """用户登出 - 使session失效"""
            try:
                session_id = g.session_id
                db = self._get_db_manager()
                session_manager = SessionManager(db)
                
                success = session_manager.invalidate_session(session_id)
                if success:
                    return jsonify({'success': True, 'message': '退出登录成功'})
                else:
                    return jsonify({'success': False, 'message': '退出登录失败'}), 500
            except Exception as e:
                logging.error(f"Logout error: {e}")
                return jsonify({'success': False, 'message': '退出登录失败'}), 500
        
        @self.app.route('/api/validate_session', methods=['POST'])
        def validate_session_api():
            """验证session API"""
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({'valid': False, 'message': '无效的请求数据'}), 400
                
                username = data.get('username')
                token = data.get('token')
                
                if not username or not token:
                    return jsonify({'valid': False, 'message': '用户名和token不能为空'}), 400
                
                db = self._get_db_manager()
                session_manager = SessionManager(db)
                
                # 验证session是否有效
                validated_username = session_manager.validate_session(token)
                
                if validated_username and validated_username == username:
                    return jsonify({
                        'valid': True,
                        'message': 'Session有效',
                        'username': validated_username
                    })
                else:
                    return jsonify({
                        'valid': False,
                        'message': 'Session无效或已过期'
                    })
                    
            except Exception as e:
                logging.error(f"Validate session API error: {e}")
                return jsonify({'valid': False, 'message': '验证失败'}), 500


        @self.app.route('/api/check_session', methods=['GET'])
        def check_session():
            """检查会话状态"""
            # 从请求头获取session ID
            session_id = request.headers.get('Authorization')
            if session_id and session_id.startswith('Bearer '):
                session_id = session_id[7:]
            else:
                session_id = request.args.get('session_id')
            
            if not session_id:
                return jsonify({'success': False, 'authenticated': False, 'message': 'No session ID provided'}), 401
            
            try:
                db = self._get_db_manager()
                session_manager = SessionManager(db)
                username = session_manager.validate_session(session_id)
                
                if username:
                    # 获取用户信息
                    user = db.select('account_data', 'username = ?', (username,))[0]
                    return jsonify({
                        'success': True,
                        'authenticated': True,
                        'userId': user['id'],
                        'username': user['username'],
                        'sessionId': session_id
                    })
                else:
                    return jsonify({'success': False, 'authenticated': False, 'message': 'Invalid or expired session'}), 401
            except Exception as e:
                logging.error(f"Check session error: {e}")
                return jsonify({'success': False, 'authenticated': False, 'message': 'Session check failed'}), 500

        @self.app.route('/api/stats', methods=['GET'])
        @self.require_session
        def get_user_stats():
            """获取用户统计信息"""
            try:
                username = g.username
                today = datetime.date.today().isoformat()
                
                with DatabaseManager(self.db_path) as db:
                    # 今日推送数
                    today_pushes = db.execute_custom_sql(
                        "SELECT COUNT(*) as count FROM push_records WHERE from_user = ? AND push_date = ?",
                        (username, today)
                    )
                    today_pushes_count = today_pushes[0]['count'] if today_pushes else 0
                    
                    # 待处理推送数
                    pending_pushes = db.execute_custom_sql(
                        "SELECT COUNT(*) as count FROM push_records WHERE from_user = ? AND status = 'pending'",
                        (username,)
                    )
                    pending_pushes_count = pending_pushes[0]['count'] if pending_pushes else 0
                    
                    # 总匹配数
                    total_matches = db.execute_custom_sql(
                        "SELECT COUNT(*) as count FROM matches WHERE (user1 = ? OR user2 = ?) AND status = 'active'",
                        (username, username)
                    )
                    total_matches_count = total_matches[0]['count'] if total_matches else 0
                    
                    # 计算接受率（已接受的推送 / 总响应的推送）
                    total_responses = db.execute_custom_sql(
                        "SELECT COUNT(*) as count FROM push_records WHERE from_user = ? AND status IN ('accepted', 'rejected')",
                        (username,)
                    )
                    total_responses_count = total_responses[0]['count'] if total_responses else 0
                    
                    accepted_responses = db.execute_custom_sql(
                        "SELECT COUNT(*) as count FROM push_records WHERE from_user = ? AND status = 'accepted'",
                        (username,)
                    )
                    accepted_responses_count = accepted_responses[0]['count'] if accepted_responses else 0
                    
                    acceptance_rate = 0
                    if total_responses_count > 0:
                        acceptance_rate = round((accepted_responses_count / total_responses_count) * 100, 1)
                    
                    stats = {
                        'today_pushes': today_pushes_count,
                        'pending_pushes': pending_pushes_count,
                        'total_matches': total_matches_count,
                        'acceptance_rate': acceptance_rate
                    }
                    
                    return jsonify({'success': True, 'stats': stats})
                    
            except Exception as e:
                logging.error(f"Get user stats error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/profile_status', methods=['GET'])
        @self.require_session
        def get_profile_status():
            """获取用户资料状态"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    # 获取用户资料
                    user_data = db.select('user_data', 'username = ?', (username,))
                    
                    if not user_data:
                        return jsonify({'success': False, 'error': '用户不存在'}), 404
                    
                    user = dict(user_data[0])
                    
                    # 检查资料完整性
                    required_fields = ['nickname', 'age', 'gender', 'bio']
                    missing_fields = []
                    
                    for field in required_fields:
                        if not user.get(field):
                            missing_fields.append(field)
                    
                    profile_complete = len(missing_fields) == 0
                    
                    # 更新数据库中的完整性状态
                    db.update('user_data', 
                             {'profile_complete': 1 if profile_complete else 0,
                              'updated_at': datetime.datetime.now().isoformat()},
                             'username = ?', 
                             (username,))
                    
                    return jsonify({
                        'success': True,
                        'profile_complete': profile_complete,
                        'missing_fields': missing_fields,
                        'profile_data': {
                            'username': user['username'],
                            'nickname': user.get('nickname', ''),
                            'age': user.get('age'),
                            'gender': user.get('gender', ''),
                            'height': user.get('height'),
                            'weight': user.get('weight'),
                            'education': user.get('education', ''),
                            'hobbies': user.get('hobbies', ''),
                            'bio': user.get('bio', ''),
                            'contact_info': user.get('contact_info', ''),
                            'created_at': user.get('created_at', ''),
                            'updated_at': user.get('updated_at', '')
                        }
                    })
                    
            except Exception as e:
                logging.error(f"Get profile status error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/update_profile', methods=['POST'])
        @self.require_session
        def update_profile():
            """更新用户资料"""
            try:
                username = g.username
                data = request.get_json()
                
                if not data:
                    return jsonify({'success': False, 'error': '无效的数据'}), 400
                
                # 移除不应该更新的字段
                data.pop('username', None)
                data.pop('id', None)
                data.pop('created_at', None)
                
                # 添加更新时间
                data['updated_at'] = datetime.datetime.now().isoformat()
                
                with DatabaseManager(self.db_path) as db:
                    # 更新用户资料
                    rows_affected = db.update('user_data', data, 'username = ?', (username,))
                    
                    if rows_affected > 0:
                        # 检查资料完整性
                        profile_complete = db.update_profile_completeness(username)
                        
                        return jsonify({
                            'success': True,
                            'message': '资料更新成功',
                            'profile_complete': profile_complete
                        })
                    else:
                        return jsonify({'success': False, 'error': '更新失败'}), 500
                        
            except Exception as e:
                logging.error(f"Update profile error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/match_preferences', methods=['GET', 'POST'])
        @self.require_session
        def handle_match_preferences():
            """处理匹配偏好（获取或设置）"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    if request.method == 'GET':
                        # 获取匹配偏好
                        preferences = db.get_match_preferences(username)
                        return jsonify({
                            'success': True,
                            'preferences': preferences
                        })
                    
                    elif request.method == 'POST':
                        # 设置匹配偏好
                        data = request.get_json()
                        
                        if not data:
                            return jsonify({'success': False, 'error': '无效的数据'}), 400
                        
                        success = db.set_match_preferences(username, data)
                        
                        if success:
                            return jsonify({
                                'success': True,
                                'message': '偏好设置成功'
                            })
                        else:
                            return jsonify({'success': False, 'error': '设置失败'}), 500
                            
            except Exception as e:
                logging.error(f"Handle match preferences error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/generate_pushes', methods=['POST'])
        @self.require_session
        def generate_pushes():
            """生成今日推送"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    # 检查资料完整性
                    profile_complete = db.check_profile_completeness(username)
                    if not profile_complete:
                        return jsonify({
                            'success': False,
                            'message': '请先完善个人资料'
                        }), 400
                    
                    # 获取潜在匹配
                    potential_matches = db.get_potential_matches(username, limit=5)
                    
                    if not potential_matches:
                        return jsonify({
                            'success': False,
                            'message': '暂无可匹配的用户'
                        })
                    
                    # 创建推送记录
                    created_count = 0
                    for match in potential_matches:
                        success = db.create_push_record(username, match['username'])
                        if success:
                            created_count += 1
                    
                    return jsonify({
                        'success': True,
                        'message': f'成功生成 {created_count} 个推送'
                    })
                    
            except Exception as e:
                logging.error(f"Generate pushes error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/daily_pushes', methods=['GET'])
        @self.require_session
        def get_daily_pushes():
            """获取今日推送"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    pushes = db.get_pending_pushes(username)
                    return jsonify({
                        'success': True,
                        'pushes': pushes
                    })
                    
            except Exception as e:
                logging.error(f"Get daily pushes error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/my_matches', methods=['GET'])
        @self.require_session
        def get_my_matches():
            """获取我的匹配"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    matches = db.get_user_matches(username)
                    return jsonify({
                        'success': True,
                        'matches': matches
                    })
                    
            except Exception as e:
                logging.error(f"Get my matches error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500