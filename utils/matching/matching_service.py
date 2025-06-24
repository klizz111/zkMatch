import logging
import datetime
from typing import List, Dict, Any, Optional
from ..database.dataBase import DatabaseManager
from ..fhe.fhe import Platform

class MatchingService:
    """匹配服务类，处理匹配推送和匹配逻辑"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def get_daily_pushes(self, username: str) -> Dict[str, Any]:
        """获取今日推送"""
        try:
            # 检查用户资料是否完整
            if not self.db.check_profile_completeness(username):
                return {
                    'success': False,
                    'error': 'Profile incomplete',
                    'message': 'Please complete your profile before receiving matches'
                }
            
            # 获取待处理的推送
            pushes = self.db.get_pending_pushes(username)
            
            return {
                'success': True,
                'pushes': pushes,
                'count': len(pushes)
            }
            
        except Exception as e:
            logging.error(f"Get daily pushes error: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_daily_pushes(self, username: str, limit: int = 5) -> Dict[str, Any]:
        """生成今日推送"""
        try:
            # 检查用户资料是否完整
            if not self.db.check_profile_completeness(username):
                return {
                    'success': False,
                    'error': 'Profile incomplete',
                    'message': 'Please complete your profile before generating matches'
                }
            
            # 获取潜在匹配对象
            potential_matches = self.db.get_potential_matches(username, limit=limit)
            
            if not potential_matches:
                return {
                    'success': True,
                    'message': 'No new matches available today',
                    'generated': 0
                }
            
            # 创建推送记录
            generated_count = 0
            for match in potential_matches:
                if self.db.create_push_record(username, match['username']):
                    generated_count += 1
            
            return {
                'success': True,
                'message': f'Generated {generated_count} new pushes',
                'generated': generated_count
            }
            
        except Exception as e:
            logging.error(f"Generate daily pushes error: {e}")
            return {'success': False, 'error': str(e)}
    
    def respond_to_push(self, username: str, push_id: int, response: str) -> Dict[str, Any]:
        """响应推送（接受/拒绝）"""
        try:
            if response not in ['accepted', 'rejected']:
                return {'success': False, 'error': 'Invalid response'}
            
            result = self.db.respond_to_push(username, push_id, response)
            return result
            
        except Exception as e:
            logging.error(f"Respond to push error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_user_matches(self, username: str) -> Dict[str, Any]:
        """获取用户的匹配列表"""
        try:
            matches = self.db.get_user_matches(username)
            
            return {
                'success': True,
                'matches': matches,
                'count': len(matches)
            }
            
        except Exception as e:
            logging.error(f"Get user matches error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_user_stats(self, username: str) -> Dict[str, Any]:
        """获取用户统计信息"""
        try:
            stats = {}
            
            # 今日推送数量
            today = datetime.date.today().isoformat()
            today_pushes = self.db.execute_custom_sql(
                "SELECT COUNT(*) as count FROM push_records WHERE from_user = ? AND push_date = ?",
                (username, today)
            )
            stats['today_pushes'] = today_pushes[0]['count'] if today_pushes else 0
            
            # 待处理推送数量（现在只显示是否有待处理的推送：0或1）
            pending_pushes = self.db.execute_custom_sql(
                "SELECT COUNT(*) as count FROM push_records WHERE from_user = ? AND status = 'pending' LIMIT 1",
                (username,)
            )
            # 如果有待处理的推送，显示1，否则显示0
            stats['pending_pushes'] = 1 if (pending_pushes and pending_pushes[0]['count'] > 0) else 0
            
            # 总匹配数量
            total_matches = self.db.execute_custom_sql(
                "SELECT COUNT(*) as count FROM matches WHERE (user1 = ? OR user2 = ?) AND status = 'active'",
                (username, username)
            )
            stats['total_matches'] = total_matches[0]['count'] if total_matches else 0
            
            return {
                'success': True,
                'stats': stats
            }
            
        except Exception as e:
            logging.error(f"Get user stats error: {e}")
            return {'success': False, 'error': str(e)}