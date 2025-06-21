from flask import request, jsonify, g
import logging
import datetime
import secrets
from ..database.dataBase import DatabaseManager

class MatchingRoutes:
    def __init__(self, app, db_path, require_session):
        self.app = app
        self.db_path = db_path
        self.require_session = require_session
        self._register_routes()

    def _register_routes(self):
        @self.app.route('/api/system_params', methods=['GET'])
        @self.require_session
        def get_system_params():
            """获取系统FHE参数"""
            try:
                with DatabaseManager(self.db_path) as db:
                    root_data = db.select('account_data', 'username = ?', ('root',))
                    if root_data:
                        params = {
                            'p': root_data[0]['p'],
                            'g': root_data[0]['g'],
                            'q': root_data[0]['q']
                        }
                        return jsonify({'success': True, 'params': params})
                    else:
                        return jsonify({'success': False, 'message': '系统参数未初始化'})
            except Exception as e:
                logging.error(f"Get system params error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/respond_push', methods=['POST'])
        @self.require_session
        def respond_push():
            """响应推送请求（拒绝情况，接受情况由安全匹配处理）"""
            try:
                username = g.username
                data = request.get_json()
                push_id = data.get('push_id')
                response = data.get('response')
                
                if not push_id or not response:
                    return jsonify({'success': False, 'message': '参数不完整'}), 400
                
                if response != 'rejected':
                    return jsonify({'success': False, 'message': '此接口仅处理拒绝响应'}), 400
                
                with DatabaseManager(self.db_path) as db:
                    # 更新推送状态为拒绝
                    rows_affected = db.update('push_records', 
                                             {'status': 'rejected', 'responded_at': datetime.datetime.now().isoformat()},
                                             'id = ? AND from_user = ?', (push_id, username))
                    
                    if rows_affected > 0:
                        return jsonify({'success': True, 'message': '已拒绝'})
                    else:
                        return jsonify({'success': False, 'message': '推送记录不存在'}), 404
                        
            except Exception as e:
                logging.error(f"Respond push error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/push_info/<int:push_id>', methods=['GET'])
        @self.require_session
        def get_push_info(push_id):
            """获取推送信息"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    push_records = db.execute_custom_sql(
                        "SELECT * FROM push_records WHERE id = ? AND from_user = ?",
                        (push_id, username)
                    )
                    
                    if not push_records:
                        return jsonify({'success': False, 'message': '推送记录不存在'}), 404
                    
                    push = push_records[0]
                    return jsonify({
                        'success': True, 
                        'push_info': {
                            'to_user': push['to_user'],
                            'push_date': push['push_date']
                        }
                    })
                    
            except Exception as e:
                logging.error(f"Get push info error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/secure_matching/submit', methods=['POST'])
        @self.require_session
        def submit_secure_matching():
            """提交安全匹配数据"""
            try:
                username = g.username
                data = request.get_json()
                
                push_id = data.get('push_id')
                dh_public_key = data.get('dh_public_key')
                choice = data.get('choice') 
                contact_info = data.get('contact_info')
                
                if not all([push_id, dh_public_key, choice is not None, contact_info]):
                    return jsonify({'success': False, 'message': '参数不完整'}), 400
                
                with DatabaseManager(self.db_path) as db:
                    # 获取推送信息
                    push_records = db.execute_custom_sql(
                        "SELECT * FROM push_records WHERE id = ? AND from_user = ?",
                        (push_id, username)
                    )
                    
                    if not push_records:
                        return jsonify({'success': False, 'message': '推送记录不存在'}), 404
                    
                    push = push_records[0]
                    to_user = push['to_user']
                    
                    # 创建或获取匹配会话
                    session_key = self._get_or_create_simple_session(db, username, to_user)
                    
                    # 确定用户在会话中的角色
                    session = db.select('simple_match_sessions', 'session_key = ?', (session_key,))[0]
                    is_user1 = (session['user1_id'] == username)
                    
                    # 更新推送状态
                    db.update('push_records', 
                             {'status': 'accepted', 
                              'responded_at': datetime.datetime.now().isoformat(),
                              'session_key': session_key},
                             'id = ?', (push_id,))
                    
                    # 保存用户数据
                    update_data = {
                        f'user{"1" if is_user1 else "2"}_dh_public': dh_public_key,
                        f'user{"1" if is_user1 else "2"}_choice': choice,
                        f'user{"1" if is_user1 else "2"}_contact': contact_info,
                        f'user{"1" if is_user1 else "2"}_responded': 1
                    }
                    
                    db.update('simple_match_sessions', update_data, 'session_key = ?', (session_key,))
                    
                    return jsonify({
                        'success': True,
                        'session_key': session_key,
                        'message': '安全匹配数据已提交'
                    })
                    
            except Exception as e:
                logging.error(f"Submit secure matching error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/secure_matching/status/<session_key>', methods=['GET'])
        @self.require_session
        def get_matching_status(session_key):
            """获取匹配状态"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    session = db.select('simple_match_sessions', 'session_key = ?', (session_key,))
                    if not session:
                        return jsonify({'success': False, 'message': '会话不存在'}), 404
                    
                    session = session[0]
                    
                    # 检查用户权限
                    if username not in [session['user1_id'], session['user2_id']]:
                        return jsonify({'success': False, 'message': '无权访问此会话'}), 403
                    
                    # 检查双方是否都已响应
                    if session['user1_responded'] and session['user2_responded']:
                        # 确定对方用户
                        is_user1 = (session['user1_id'] == username)
                        other_user_prefix = 'user2' if is_user1 else 'user1'
                        
                        return jsonify({
                            'success': True,
                            'ready': True,
                            'other_public_key': session[f'{other_user_prefix}_dh_public'],
                            'other_choice_cipher': [session[f'{other_user_prefix}_choice'], 0],  # 简化格式
                            'other_contact_data': [session[f'{other_user_prefix}_contact'], '']  # 简化格式
                        })
                    else:
                        return jsonify({
                            'success': True,
                            'ready': False,
                            'message': '等待对方响应'
                        })
                        
            except Exception as e:
                logging.error(f"Get matching status error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/secure_matching/results', methods=['GET'])
        @self.require_session
        def get_secure_results():
            """获取安全匹配结果列表"""
            try:
                username = g.username
                
                with DatabaseManager(self.db_path) as db:
                    # 获取用户参与的匹配会话
                    sessions = db.execute_custom_sql(
                        """SELECT s.*, u.nickname as other_nickname
                           FROM simple_match_sessions s
                           LEFT JOIN user_data u ON (
                               CASE WHEN s.user1_id = ? THEN s.user2_id ELSE s.user1_id END = u.username
                           )
                           WHERE (s.user1_id = ? OR s.user2_id = ?) 
                           ORDER BY s.created_at DESC""",
                        (username, username, username)
                    )
                    
                    results = []
                    for session in sessions:
                        # 检查匹配状态
                        status = 'completed' if (session['user1_responded'] and session['user2_responded']) else 'pending'
                        
                        is_match = None
                        contact_info = None
                        
                        if status == 'completed':
                            # 简单逻辑：双方都同意才匹配成功
                            user1_choice = session['user1_choice']
                            user2_choice = session['user2_choice']
                            is_match = bool(user1_choice and user2_choice)
                            
                            if is_match:
                                # 获取对方联系方式
                                is_user1 = (session['user1_id'] == username)
                                contact_info = session['user2_contact'] if is_user1 else session['user1_contact']
                        
                        results.append({
                            'session_key': session['session_key'],
                            'other_nickname': session['other_nickname'],
                            'created_at': session['created_at'],
                            'status': status,
                            'is_match': is_match,
                            'contact_info': contact_info
                        })
                    
                    return jsonify({'success': True, 'results': results})
                    
            except Exception as e:
                logging.error(f"Get secure results error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        def _get_or_create_simple_session(self, db, user1, user2):
            """获取或创建简单匹配会话"""
            # 确保用户顺序一致
            if user1 > user2:
                user1, user2 = user2, user1
                
            # 检查是否已存在会话
            existing = db.select('simple_match_sessions', 'user1_id = ? AND user2_id = ?', (user1, user2))
            
            if existing:
                return existing[0]['session_key']
            
            # 创建新会话
            session_key = secrets.token_urlsafe(32)
            session_data = {
                'session_key': session_key,
                'user1_id': user1,
                'user2_id': user2,
                'created_at': datetime.datetime.now().isoformat(),
                'user1_responded': 0,
                'user2_responded': 0
            }
            
            db.insert('simple_match_sessions', session_data)
            return session_key

