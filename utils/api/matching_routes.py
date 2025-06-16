from flask import request, jsonify, g
from ..matching import MatchingService, ProfileService
from ..database.dataBase import DatabaseManager

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
            response = data.get('response')
            
            if not push_id or response not in ['accepted', 'rejected']:
                return jsonify({'error': 'Invalid push_id or response'}), 400
            
            db = self._get_db_manager()
            matching_service = MatchingService(db)
            result = matching_service.respond_to_push(username, push_id, response)
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
        
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