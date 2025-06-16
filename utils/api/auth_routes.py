from flask import request, jsonify, g
from functools import wraps
from ..auth import AuthService, SessionManager
from ..database.dataBase import DatabaseManager

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
                session_id = request.args.get('session_id') or request.json.get('session_id') if request.json else None
            
            if not session_id:
                return jsonify({'error': 'Session ID required'}), 401
            
            db = self._get_db_manager()
            session_manager = SessionManager(db)
            username = session_manager.validate_session(session_id)
            
            if not username:
                return jsonify({'error': 'Invalid or expired session'}), 401
            
            # 将用户名添加到g对象中，方便路由函数使用
            g.current_user = username
            return f(*args, **kwargs)
        
        return decorated_function
    
    def _register_routes(self):
        """注册所有认证相关的路由"""
        
        @self.app.route('/api/register', methods=['POST'])
        def register():
            """用户注册API - 第一步：获取群参数"""
            data = request.get_json()
            username = data.get('username')
            
            if not username :
                return jsonify({'error': 'Username are required'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.register_user_step1(username)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 409 if 'already exists' in result['error'] else 500
                return jsonify(result), status_code
        
        @self.app.route('/api/complete_registration', methods=['POST'])
        def complete_registration():
            """完成用户注册 - 第二步：客户端发送公钥"""
            data = request.get_json()
            username = data.get('username')
            y = data.get('y')
            
            if not username or not y:
                return jsonify({'error': 'Username and public key y are required'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.register_user_step2(username, y)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 404 if 'not found' in result['error'] else 500
                return jsonify(result), status_code
        
        @self.app.route('/api/login_challenge', methods=['POST'])
        def login_challenge():
            """登录 - 第一步：获取pgy"""
            data = request.get_json()
            username = data.get('username')
            
            if not username:
                return jsonify({'error': 'Username is required'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.get_login_challenge(username)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 404 if 'not found' in result['error'] else 500
                return jsonify(result), status_code
        
        @self.app.route('/api/login_verify', methods=['POST'])
        def login_verify():
            """登录 - 第二步：验证零知识证明"""
            data = request.get_json()
            username = data.get('username')
            
            try:
                proof_c = int(data.get('proof_c'))
                proof_z = int(data.get('proof_z'))
            except (TypeError, ValueError):
                return jsonify({'error': 'Invalid proof format'}), 400
            
            if not username:
                return jsonify({'error': 'Username is required'}), 400
            
            db = self._get_db_manager()
            auth_service = AuthService(db)
            result = auth_service.verify_login_proof(username, proof_c, proof_z)
            
            if result['success']:
                return jsonify(result)
            else:
                status_code = 401 if 'Invalid proof' in result['error'] else 500
                return jsonify(result), status_code
        
        @self.app.route('/api/logout', methods=['POST'])
        @self.require_session
        def logout():
            """用户登出 - 使session失效"""
            # 从请求头获取session ID
            session_id = request.headers.get('Authorization')
            if session_id and session_id.startswith('Bearer '):
                session_id = session_id[7:]
            else:
                session_id = request.args.get('session_id') or request.json.get('session_id') if request.json else None
            
            if session_id:
                db = self._get_db_manager()
                session_manager = SessionManager(db)
                success = session_manager.invalidate_session(session_id)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': 'Logged out successfully'
                    })
                else:
                    return jsonify({'error': 'Failed to logout'}), 500
            else:
                return jsonify({'error': 'Session ID not found'}), 400
        
        @self.app.route('/api/validate_session', methods=['GET'])
        def validate_session():
            """验证session是否有效"""
            session_id = request.headers.get('Authorization')
            if session_id and session_id.startswith('Bearer '):
                session_id = session_id[7:]
            else:
                session_id = request.args.get('session_id')
            
            if not session_id:
                return jsonify({'valid': False, 'error': 'Session ID required'}), 400
            
            db = self._get_db_manager()
            session_manager = SessionManager(db)
            username = session_manager.validate_session(session_id)
            
            if username:
                return jsonify({
                    'valid': True,
                    'username': username
                })
            else:
                return jsonify({'valid': False})