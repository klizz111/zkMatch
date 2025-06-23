from flask import Blueprint, request, jsonify
import logging
from ..database.dataBase import DatabaseManager
from ..auth.session_manager import SessionManager
from ..fhe.fhe_manager import FHEMatchingManager
import json
import datetime

fhe_matching_bp = Blueprint('fhe_matching', __name__)

# 初始化管理器
db = DatabaseManager('datastorage.db')
session_manager = SessionManager(db)
fhe_manager = FHEMatchingManager(db)

@fhe_matching_bp.route('/api/system_params', methods=['GET'])
def get_system_params():
    """获取系统ElGamal参数"""
    try:
        params = fhe_manager.elgamal_params
        return jsonify({
            'success': True,
            'params': {
                'p': str(params['p']),
                'g': str(params['g']),
                'q': str(params['q'])
            }
        })
    except Exception as e:
        logging.error(f"Get system params error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@fhe_matching_bp.route('/api/daily_pushes', methods=['GET'])
def get_daily_pushes():
    """获取今日推送（使用FHE匹配流程）"""
    try:
        # 验证session
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': '未授权访问'}), 401
        
        session_id = auth_header.split(' ')[1]
        username = session_manager.validate_session(session_id)
        if not username:
            return jsonify({'success': False, 'error': '会话已过期'}), 401
        
        # 检查用户资料完整性
        with db:
            if not db.check_profile_completeness(username):
                return jsonify({
                    'success': False, 
                    'error': '请先完善个人资料'
                }), 400
            
            # 获取潜在匹配用户
            potential_matches = db.get_potential_matches(username, limit=5)
            
            if not potential_matches:
                return jsonify({
                    'success': True,
                    'pushes': [],
                    'message': '暂无可匹配的用户'
                })
            
            # 为每个匹配用户创建FHE会话
            pushes = []
            user_account = db.select('account_data', 'username = ?', (username,))
            if not user_account:
                return jsonify({'success': False, 'error': '用户账户不存在'}), 400
            
            user_dh_public = int(user_account[0]['y'])
            
            for match in potential_matches:
                target_username = match['username']
                
                # 获取目标用户的DH公钥
                target_account = db.select('account_data', 'username = ?', (target_username,))
                if not target_account:
                    continue
                
                target_dh_public = int(target_account[0]['y'])
                
                # 创建FHE会话
                try:
                    session_key = fhe_manager.create_fhe_session(
                        username, target_username, user_dh_public, target_dh_public
                    )
                    
                    # 准备推送数据
                    push_data = {
                        'push_id': session_key,  # 使用session_key作为push_id
                        'session_key': session_key,
                        'target_user': target_username,
                        'target_dh_public': str(target_dh_public),
                        'user_info': {
                            'username': match['username'],
                            'nickname': match['nickname'],
                            'age': match['age'],
                            'gender': match['gender'],
                            'height': match['height'],
                            'education': match['education'],
                            'hobbies': match['hobbies'],
                            'bio': match['bio']
                        }
                    }
                    pushes.append(push_data)
                    
                except Exception as e:
                    logging.error(f"Create FHE session error for {target_username}: {e}")
                    continue
            
            return jsonify({
                'success': True,
                'pushes': pushes
            })
        
    except Exception as e:
        logging.error(f"Get daily pushes error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@fhe_matching_bp.route('/api/submit_choice', methods=['POST'])
def submit_choice():
    """提交用户选择（FHE加密）"""
    try:
        # 验证session
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': '未授权访问'}), 401
        
        session_id = auth_header.split(' ')[1]
        username = session_manager.validate_session(session_id)
        if not username:
            return jsonify({'success': False, 'error': '会话已过期'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '无效的请求数据'}), 400
        
        required_fields = ['session_key', 'choice_cipher', 'contact_data']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'缺少字段: {field}'}), 400
        
        session_key = data['session_key']
        choice_cipher = tuple(data['choice_cipher'])
        contact_data_raw = data['contact_data']
        
        # 解析联系方式数据
        encrypted_contact = bytes.fromhex(contact_data_raw['encrypted_contact'])
        contact_key_cipher = tuple(contact_data_raw['contact_key_cipher'])
        contact_data = (encrypted_contact, contact_key_cipher)
        
        # 提交选择
        success = fhe_manager.submit_user_choice(session_key, username, choice_cipher, contact_data)
        
        if success:
            return jsonify({
                'success': True,
                'message': '选择提交成功'
            })
        else:
            return jsonify({
                'success': False,
                'error': '提交失败'
            }), 400
        
    except Exception as e:
        logging.error(f"Submit choice error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@fhe_matching_bp.route('/api/get_match_result', methods=['GET'])
def get_match_result():
    """获取匹配结果"""
    try:
        # 验证session
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': '未授权访问'}), 401
        
        session_id = auth_header.split(' ')[1]
        username = session_manager.validate_session(session_id)
        if not username:
            return jsonify({'success': False, 'error': '会话已过期'}), 401
        
        session_key = request.args.get('session_key')
        if not session_key:
            return jsonify({'success': False, 'error': '缺少session_key参数'}), 400
        
        # 检查会话状态
        with db:
            session_data = db.select('fhe_match_sessions', 'session_key = ?', (session_key,))
            if not session_data:
                return jsonify({'success': False, 'error': '会话不存在'}), 404
            
            session_info = dict(session_data[0])
            
            # 检查用户是否在此会话中
            if username not in [session_info['user1_id'], session_info['user2_id']]:
                return jsonify({'success': False, 'error': '无权访问此会话'}), 403
            
            # 检查当前用户是否已响应
            user_responded = (session_info['user1_responded'] if username == session_info['user1_id'] 
                            else session_info['user2_responded'])
            
            if not user_responded:
                return jsonify({
                    'success': False,
                    'error': '您尚未提交选择'
                }), 400
            
            # 如果结果已计算（双方都已响应），返回真实结果
            if session_info['result_computed']:
                result = fhe_manager.get_match_result(session_key, username)
                if result:
                    return jsonify({
                        'success': True,
                        'result_computed': True,
                        'result': {
                            'result_cipher': result['result_cipher'],
                            'contact_key_cipher': result['contact_key_cipher'],
                            'contact_encrypted': result['contact_encrypted'].hex()
                        }
                    })
            else:
                # 如果只有一方响应，生成虚假结果
                # 获取用户的共享密钥参数来生成虚假结果
                user_account = db.select('account_data', 'username = ?', (username,))
                if user_account:
                    user_y = int(user_account[0]['y'])
                    fake_result = fhe_manager.generate_fake_result(user_y)
                    
                    return jsonify({
                        'success': True,
                        'result_computed': False,
                        'result': {
                            'result_cipher': fake_result['result_cipher'],
                            'contact_key_cipher': fake_result['contact_key_cipher'],
                            'contact_encrypted': fake_result['contact_encrypted'].hex()
                        }
                    })
            
            return jsonify({'success': False, 'error': '无法获取结果'}), 500
        
    except Exception as e:
        logging.error(f"Get match result error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@fhe_matching_bp.route('/api/my_matches', methods=['GET'])
def get_my_matches():
    """获取我的匹配（基于FHE解密成功的结果）"""
    try:
        # 验证session
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': '未授权访问'}), 401
        
        session_id = auth_header.split(' ')[1]
        username = session_manager.validate_session(session_id)
        if not username:
            return jsonify({'success': False, 'error': '会话已过期'}), 401
        
        with db:
            # 获取用户参与的所有已完成的FHE会话
            matches = db.execute_custom_sql("""
                SELECT fs.*, sr.is_match, sr.contact_info, sr.decrypted_at
                FROM fhe_match_sessions fs
                LEFT JOIN secure_match_results sr ON fs.session_key = sr.session_key AND sr.user_id = ?
                WHERE (fs.user1_id = ? OR fs.user2_id = ?) 
                AND fs.result_computed = 1
                ORDER BY fs.created_at DESC
            """, (username, username, username))
            
            result_matches = []
            for match in matches:
                # 确定对方用户
                other_user = match['user2_id'] if match['user1_id'] == username else match['user1_id']
                
                # 获取对方用户信息
                other_user_info = db.select('user_data', 'username = ?', (other_user,))
                if not other_user_info:
                    continue
                
                other_user_data = dict(other_user_info[0])
                
                match_info = {
                    'session_key': match['session_key'],
                    'matched_user': {
                        'username': other_user_data['username'],
                        'nickname': other_user_data['nickname'],
                        'age': other_user_data['age'],
                        'gender': other_user_data['gender'],
                        'bio': other_user_data['bio']
                    },
                    'match_date': match['created_at'],
                    'is_match': bool(match['is_match']) if match['is_match'] is not None else None,
                    'contact_info': match['contact_info'] if match['contact_info'] else None,
                    'decrypted_at': match['decrypted_at']
                }
                
                # 如果有解密的联系方式，说明匹配成功
                if match['contact_info']:
                    match_info['matched_user']['contact_info'] = match['contact_info']
                
                result_matches.append(match_info)
            
            return jsonify({
                'success': True,
                'matches': result_matches
            })
        
    except Exception as e:
        logging.error(f"Get my matches error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@fhe_matching_bp.route('/api/save_match_result', methods=['POST'])
def save_match_result():
    """保存解密后的匹配结果"""
    try:
        # 验证session
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': '未授权访问'}), 401
        
        session_id = auth_header.split(' ')[1]
        username = session_manager.validate_session(session_id)
        if not username:
            return jsonify({'success': False, 'error': '会话已过期'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '无效的请求数据'}), 400
        
        session_key = data.get('session_key')
        is_match = data.get('is_match')
        contact_info = data.get('contact_info')
        
        if session_key is None or is_match is None:
            return jsonify({'success': False, 'error': '缺少必要参数'}), 400
        
        with db:
            # 删除可能存在的旧记录
            db.delete('secure_match_results', 'session_key = ? AND user_id = ?', (session_key, username))
            
            # 插入新记录
            result_data = {
                'session_key': session_key,
                'user_id': username,
                'is_match': bool(is_match),
                'contact_info': contact_info,
                'decrypted_at': datetime.datetime.now().isoformat()
            }
            
            db.insert('secure_match_results', result_data)
            
            return jsonify({
                'success': True,
                'message': '匹配结果已保存'
            })
        
    except Exception as e:
        logging.error(f"Save match result error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@fhe_matching_bp.route('/api/generate_pushes', methods=['POST'])
def generate_pushes():
    """生成新推送（实际上是刷新可用的匹配用户）"""
    try:
        # 验证session
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': '未授权访问'}), 401
        
        session_id = auth_header.split(' ')[1]
        username = session_manager.validate_session(session_id)
        if not username:
            return jsonify({'success': False, 'error': '会话已过期'}), 401
        
        # 清理过期的会话
        fhe_manager.cleanup_expired_sessions(hours=1)
        
        return jsonify({
            'success': True,
            'message': '推送已刷新，请重新加载'
        })
        
    except Exception as e:
        logging.error(f"Generate pushes error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500