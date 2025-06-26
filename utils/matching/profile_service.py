import logging
import datetime
from typing import List, Dict, Any, Optional
from ..database.dataBase import DatabaseManager

class ProfileService:
    """用户资料服务类，处理用户资料相关逻辑"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def get_user_profile(self, username: str) -> Dict[str, Any]:
        """获取用户资料"""
        try:
            user_record = self.db.select('user_data', 'username = ?', (username,))
            
            if not user_record:
                return {'success': False, 'error': 'User not found'}
            
            user = user_record[0]
            return {
                'success': True,
                'profile': {
                    'username': user['username'],
                    'nickname': user['nickname'],
                    'age': user['age'],
                    'gender': user['gender'],
                    'height': user['height'],
                    'weight': user['weight'],
                    'education': user['education'],
                    'occupation': user['occupation'],
                    'hobbies': user['hobbies'],
                    'bio': user['bio'],
                    'location': user['location'],
                    'contact_info': user['contact_info'],
                    'personal_info': user['personal_info']
                }
            }
            
        except Exception as e:
            logging.error(f"Get user profile error: {e}")
            return {'success': False, 'error': str(e)}
    
    def update_user_profile(self, username: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """更新用户资料"""
        try:
            # 允许更新的字段
            allowed_fields = ['nickname', 'age', 'gender', 'height', 'weight', 
                             'education', 'occupation', 'hobbies', 'bio', 'location',
                             'personal_info']
            
            update_data = {}
            for field in allowed_fields:
                if field in profile_data:
                    update_data[field] = profile_data[field]
            
            if not update_data:
                return {'success': False, 'error': 'No valid fields to update'}
            
            # 添加更新时间
            update_data['updated_at'] = datetime.datetime.now().isoformat()
            
            rows_affected = self.db.update('user_data', update_data, 'username = ?', (username,))
            
            if rows_affected > 0:
                # 更新资料完整性状态
                is_complete = self.db.update_profile_completeness(username)
                
                return {
                    'success': True,
                    'message': 'Profile updated successfully',
                    'profile_complete': is_complete
                }
            else:
                return {'success': False, 'error': 'User not found'}
                
        except Exception as e:
            logging.error(f"Update user profile error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_profile_status(self, username: str) -> Dict[str, Any]:
        """获取用户资料完整性状态"""
        try:
            user_info = self.db.select('user_data', 'username = ?', (username,))
            if not user_info:
                return {'success': False, 'error': 'User not found'}
            
            user = dict(user_info[0])
            is_complete = self.db.check_profile_completeness(username)
            
            # 检查缺少的必填字段
            required_fields = ['nickname', 'age', 'gender', 'bio']
            missing_fields = []
            
            for field in required_fields:
                if not user.get(field):
                    missing_fields.append(field)
            
            return {
                'success': True,
                'profile_complete': is_complete,
                'missing_fields': missing_fields,
                'profile_data': {
                    'nickname': user.get('nickname'),
                    'age': user.get('age'),
                    'gender': user.get('gender'),
                    'height': user.get('height'),
                    'weight': user.get('weight'),
                    'education': user.get('education'),
                    'occupation': user.get('occupation'),
                    'hobbies': user.get('hobbies'),
                    'bio': user.get('bio'),
                    'location': user.get('location')
                }
            }
            
        except Exception as e:
            logging.error(f"Get profile status error: {e}")
            return {'success': False, 'error': str(e)}
    
    def set_match_preferences(self, username: str, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """设置匹配偏好"""
        try:
            # 允许设置的偏好字段
            allowed_prefs = ['preferred_gender', 'min_age', 'max_age', 
                           'min_height', 'max_height', 'preferred_education',
                           'preferred_location', 'deal_breakers']
            
            valid_preferences = {}
            for field in allowed_prefs:
                if field in preferences:
                    valid_preferences[field] = preferences[field]
            
            if not valid_preferences:
                return {'success': False, 'error': 'No valid preferences provided'}
            
            success = self.db.set_match_preferences(username, valid_preferences)
            
            if success:
                return {
                    'success': True,
                    'message': 'Preferences updated successfully'
                }
            else:
                return {'success': False, 'error': 'Failed to update preferences'}
                
        except Exception as e:
            logging.error(f"Set match preferences error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_match_preferences(self, username: str) -> Dict[str, Any]:
        """获取匹配偏好"""
        try:
            prefs = self.db.get_match_preferences(username)
            if prefs:
                return {
                    'success': True,
                    'preferences': prefs
                }
            else:
                return {
                    'success': True,
                    'preferences': None,
                    'message': 'No preferences set'
                }
                
        except Exception as e:
            logging.error(f"Get match preferences error: {e}")
            return {'success': False, 'error': str(e)}