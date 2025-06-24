import logging
from typing import Optional, Dict, Any
from ..database.dataBase import DatabaseManager
from ..zk.dlogProof import dlogProofVerify

class AuthService:
    """认证服务类，处理用户注册和登录逻辑"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def register_user_step1(self, username: str) -> Dict[str, Any]:
        """用户注册第一步：获取群参数"""
        try:
            # 检查用户名是否已存在
            existing_user = self.db.select('account_data', 'username = ?', (username,))
            if existing_user:
                return {'success': False, 'error': 'Username already exists'}
            
            # 从root用户获取群参数
            root_record = self.db.select('account_data', 'username = ?', ('root',))
            if not root_record:
                return {'success': False, 'error': 'System not initialized - root user not found'}
            
            root_data = root_record[0]
            p = root_data['p']
            g = root_data['g']
            q = root_data['q']
            
            # 创建用户记录（y将由客户端计算并在第二步发送）
            account_data = {
                'username': username,
                'p': p,
                'g': g,
                'q': q,
                'y': '',  # 暂时为空，等待客户端计算
                'compressed_credential': '',  # 暂时为空
                'bits': 512  # 固定为512位
            }
            
            self.db.insert('account_data', account_data)
            
            return {
                'success': True,
                'p': p,
                'g': g,
                'q': q
            }
            
        except Exception as e:
            logging.error(f"Register step 1 error: {e}")
            return {'success': False, 'error': str(e)}
    
    def register_user_step2(self, username: str, y: str) -> Dict[str, Any]:
        """用户注册第二步：完成注册"""
        try:
            # 查找用户记录
            user_record = self.db.select('account_data', 'username = ?', (username,))
            if not user_record:
                return {'success': False, 'error': 'User not found'}
            
            # 更新账户数据
            update_data = {
                'y': str(y),
                'compressed_credential': ''
            }
            
            self.db.update('account_data', update_data, 'username = ?', (username,))
            
            # 在用户表中创建记录
            user_data = {
                'username': username,
                'nickname': username,  # 默认昵称为用户名
                'age': None,
                'personal_info': None
            }
            
            try:
                self.db.insert('user_data', user_data)
                # print("User data inserted successfully")
            except:
                pass  # 如果已存在则忽略
            
            return {
                'success': True,
                'message': 'Registration completed successfully'
            }
            
        except Exception as e:
            logging.error(f"Register step 2 error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_login_challenge(self, username: str) -> Dict[str, Any]:
        """获取登录挑战"""
        try:
            # 从数据库获取用户信息
            user_record = self.db.select('account_data', 'username = ?', (username,))
            if not user_record:
                return {'success': False, 'error': 'User not found'}
            
            user_data = user_record[0]
            p = int(user_data['p'])
            g = int(user_data['g'])
            y = int(user_data['y'])
            
            return {
                'success': True,
                'p': str(p),
                'g': str(g),
                'y': str(y)
            }
            
        except Exception as e:
            logging.error(f"Get login challenge error: {e}")
            return {'success': False, 'error': str(e)}
    
    def verify_login_proof(self, username: str, proof_c: int, proof_z: int) -> Dict[str, Any]:
        """验证零知识证明"""
        try:
            # 获取用户信息
            user_record = self.db.select('account_data', 'username = ?', (username,))
            if not user_record:
                return {'success': False, 'error': 'User not found'}
            
            user_data = user_record[0]
            p = int(user_data['p'])
            g = int(user_data['g'])
            y = int(user_data['y'])
            
            # 验证零知识证明
            proof = (proof_c, proof_z)
            is_valid = dlogProofVerify(y, g, p, proof)
            
            if is_valid:
                # 登录成功，生成session ID
                session_id = self.db.generate_session_id(username)
                
                return {
                    'success': True,
                    'message': 'Login successful',
                    'session_id': session_id,
                    'user_info': {
                        'username': username
                    }
                }
            else:
                return {'success': False, 'error': 'Invalid proof'}
            
        except Exception as e:
            logging.error(f"Verify login proof error: {e}")
            return {'success': False, 'error': str(e)}