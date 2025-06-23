import os
import json
import hashlib
import secrets
from typing import Dict, Tuple, Optional, List, Any
from Crypto.Cipher import AES
from Crypto.Random import random as crypto_random
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
import logging
from ..elgamal.elgamal import ElGamal
from ..database.dataBase import DatabaseManager

class FHEMatchingManager:
    """同态加密匹配管理器"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.elgamal_params = self._get_system_params()
        
    def _get_system_params(self) -> Dict[str, int]:
        """获取系统ElGamal参数"""
        try:
            with self.db:
                root_account = self.db.select('account_data', 'username = ?', ('root',))
                if root_account:
                    root = dict(root_account[0])
                    return {
                        'p': int(root['p']),
                        'g': int(root['g']),
                        'q': int(root['q'])
                    }
                else:
                    # 如果没有root参数，创建新的
                    elgamal = ElGamal(bits=512)
                    elgamal.keygen()
                    params = {
                        'p': elgamal.p,
                        'g': elgamal.g,
                        'q': elgamal.q
                    }
                    
                    root_data = {
                        'username': 'root',
                        'p': str(params['p']),
                        'g': str(params['g']),
                        'q': str(params['q']),
                        'y': str(elgamal.y),
                        'compressed_credential': '',
                        'bits': 512
                    }
                    self.db.insert('account_data', root_data)
                    return params
        except Exception as e:
            logging.error(f"Error getting system params: {e}")
            raise
    
    def generate_dh_keypair(self) -> Tuple[int, int]:
        """生成Diffie-Hellman密钥对"""
        private_key = crypto_random.randrange(1, self.elgamal_params['q'])
        public_key = pow(self.elgamal_params['g'], private_key, self.elgamal_params['p'])
        return private_key, public_key
    
    def compute_shared_secret(self, my_private_key: int, other_public_key: int) -> Tuple[int, int, int]:
        """计算共享密钥"""
        shared_secret = pow(other_public_key, my_private_key, self.elgamal_params['p'])
        
        # 派生ElGamal私钥
        hash_input = str(shared_secret).encode()
        hash_digest = hashlib.sha256(hash_input).digest()
        shared_private_key = int.from_bytes(hash_digest[:32], 'big') % self.elgamal_params['q']
        if shared_private_key == 0:
            shared_private_key = 1
            
        shared_y = pow(self.elgamal_params['g'], shared_private_key, self.elgamal_params['p'])
        
        return shared_secret, shared_private_key, shared_y
    
    def prepare_contact_info(self, contact_info: str, shared_y: int) -> Tuple[bytes, Tuple[int, int]]:
        """准备加密的联系方式"""
        # 生成联系方式加密密钥
        contact_key_int = crypto_random.randrange(1, min(2**128, self.elgamal_params['q']))
        contact_key_bytes = contact_key_int.to_bytes(32, 'big')
        
        # 使用AES加密联系方式
        cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
        padded_contact = pad(contact_info.encode('utf-8'), AES.block_size)
        encrypted_contact = cipher.encrypt(padded_contact)
        
        # 使用ElGamal加密联系方式密钥
        k = crypto_random.randrange(1, self.elgamal_params['q'])
        c1 = pow(self.elgamal_params['g'], k, self.elgamal_params['p'])
        c2 = (contact_key_int * pow(shared_y, k, self.elgamal_params['p'])) % self.elgamal_params['p']
        
        return encrypted_contact, (c1, c2)
    
    def encrypt_choice(self, choice: bool, shared_y: int) -> Tuple[Tuple[int, int], int]:
        """加密匹配选择"""
        if choice:
            message = 1  # 接受
        else:
            message = crypto_random.randrange(2, self.elgamal_params['q'])  # 拒绝：随机数
        
        # 使用ElGamal加密
        k = crypto_random.randrange(1, self.elgamal_params['q'])
        c1 = pow(self.elgamal_params['g'], k, self.elgamal_params['p'])
        c2 = (message * pow(shared_y, k, self.elgamal_params['p'])) % self.elgamal_params['p']
        
        return (c1, c2), message
    
    def homomorphic_multiplication(self, cipher1: Tuple[int, int], cipher2: Tuple[int, int]) -> Tuple[int, int]:
        """同态乘法运算"""
        c1_1, c2_1 = cipher1
        c1_2, c2_2 = cipher2
        
        c1_result = (c1_1 * c1_2) % self.elgamal_params['p']
        c2_result = (c2_1 * c2_2) % self.elgamal_params['p']
        
        return (c1_result, c2_result)
    
    def rerandomize(self, ciphertext: Tuple[int, int]) -> Tuple[int, int]:
        """对密文进行再随机化"""
        c1, c2 = ciphertext
        
        r = crypto_random.randrange(1, self.elgamal_params['q'])
        c1_new = pow(c1, r, self.elgamal_params['p'])
        c2_new = pow(c2, r, self.elgamal_params['p'])
        
        return (c1_new, c2_new)
    
    def decrypt_result(self, ciphertext: Tuple[int, int], shared_private_key: int) -> Tuple[bool, int]:
        """解密匹配结果"""
        c1, c2 = ciphertext
        
        s = pow(c1, shared_private_key, self.elgamal_params['p'])
        s_inv = pow(s, -1, self.elgamal_params['p'])
        result = (c2 * s_inv) % self.elgamal_params['p']
        
        is_match = (result == 1)
        return is_match, result
    
    def decrypt_contact_info(self, processed_contact_key_cipher: Tuple[int, int], 
                           encrypted_contact: bytes, shared_private_key: int) -> Optional[str]:
        """解密联系方式"""
        try:
            c1, c2 = processed_contact_key_cipher
            
            # 解密经过同态处理的密钥密文
            s = pow(c1, shared_private_key, self.elgamal_params['p'])
            s_inv = pow(s, -1, self.elgamal_params['p'])
            decrypted_value = (c2 * s_inv) % self.elgamal_params['p']
            
            try:
                contact_key_bytes = decrypted_value.to_bytes(32, 'big')
                cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
                padded_plaintext = cipher.decrypt(encrypted_contact)
                contact_info = unpad(padded_plaintext, AES.block_size).decode('utf-8')
                return contact_info
            except (ValueError, UnicodeDecodeError, OverflowError):
                # 解密失败，说明匹配失败或密钥无效
                return None
                
        except Exception as e:
            logging.error(f"Contact info decryption error: {e}")
            return None
    
    def create_fhe_session(self, user1_id: str, user2_id: str, 
                          user1_dh_public: int, user2_dh_public: int) -> str:
        """创建FHE匹配会话"""
        try:
            session_key = secrets.token_urlsafe(32)
            
            session_data = {
                'session_key': session_key,
                'user1_id': user1_id,
                'user2_id': user2_id,
                'user1_dh_public': str(user1_dh_public),
                'user2_dh_public': str(user2_dh_public),
                'user1_responded': 0,
                'user2_responded': 0,
                'result_computed': 0
            }
            
            with self.db:
                # 删除可能存在的旧会话
                self.db.delete('fhe_match_sessions', 
                              '(user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)',
                              (user1_id, user2_id, user2_id, user1_id))
                
                self.db.insert('fhe_match_sessions', session_data)
                
            return session_key
            
        except Exception as e:
            logging.error(f"Create FHE session error: {e}")
            raise
    
    def submit_user_choice(self, session_key: str, user_id: str, 
                          choice_cipher: Tuple[int, int], contact_data: Tuple[bytes, Tuple[int, int]]) -> bool:
        """提交用户选择和联系方式"""
        try:
            with self.db:
                session = self.db.select('fhe_match_sessions', 'session_key = ?', (session_key,))
                if not session:
                    return False
                
                session_data = dict(session[0])
                encrypted_contact, contact_key_cipher = contact_data
                
                update_data = {}
                if user_id == session_data['user1_id']:
                    update_data = {
                        'user1_choice_cipher': json.dumps(choice_cipher),
                        'user1_contact_data': json.dumps({
                            'encrypted_contact': encrypted_contact.hex(),
                            'contact_key_cipher': contact_key_cipher
                        }),
                        'user1_responded': 1
                    }
                elif user_id == session_data['user2_id']:
                    update_data = {
                        'user2_choice_cipher': json.dumps(choice_cipher),
                        'user2_contact_data': json.dumps({
                            'encrypted_contact': encrypted_contact.hex(),
                            'contact_key_cipher': contact_key_cipher
                        }),
                        'user2_responded': 1
                    }
                else:
                    return False
                
                self.db.update('fhe_match_sessions', update_data, 'session_key = ?', (session_key,))
                
                # 检查是否双方都已响应
                updated_session = self.db.select('fhe_match_sessions', 'session_key = ?', (session_key,))
                if updated_session:
                    session_info = dict(updated_session[0])
                    if session_info['user1_responded'] and session_info['user2_responded']:
                        self._compute_match_result(session_key)
                
                return True
                
        except Exception as e:
            logging.error(f"Submit user choice error: {e}")
            return False
    
    def _compute_match_result(self, session_key: str) -> bool:
        """计算匹配结果（双方都响应后）"""
        try:
            with self.db:
                session = self.db.select('fhe_match_sessions', 'session_key = ?', (session_key,))
                if not session:
                    return False
                
                session_data = dict(session[0])
                
                # 解析加密数据
                user1_choice_cipher = tuple(json.loads(session_data['user1_choice_cipher']))
                user2_choice_cipher = tuple(json.loads(session_data['user2_choice_cipher']))
                
                user1_contact_data = json.loads(session_data['user1_contact_data'])
                user2_contact_data = json.loads(session_data['user2_contact_data'])
                
                user1_contact_key_cipher = tuple(user1_contact_data['contact_key_cipher'])
                user2_contact_key_cipher = tuple(user2_contact_data['contact_key_cipher'])
                
                # 同态乘法处理匹配选择
                result_cipher = self.homomorphic_multiplication(user1_choice_cipher, user2_choice_cipher)
                final_result_cipher = self.rerandomize(result_cipher)
                
                # 同态绑定联系方式密钥
                user1_gets_contact_key = self.homomorphic_multiplication(final_result_cipher, user2_contact_key_cipher)
                user2_gets_contact_key = self.homomorphic_multiplication(final_result_cipher, user1_contact_key_cipher)
                
                # 更新会话数据
                update_data = {
                    'result_cipher': json.dumps(final_result_cipher),
                    'result_computed': 1
                }
                
                self.db.update('fhe_match_sessions', update_data, 'session_key = ?', (session_key,))
                
                # 存储用户可获取的数据
                user1_result_data = {
                    'session_key': session_key,
                    'user_id': session_data['user1_id'],
                    'result_cipher': json.dumps(final_result_cipher),
                    'contact_key_cipher': json.dumps(user1_gets_contact_key),
                    'contact_encrypted': user2_contact_data['encrypted_contact']
                }
                
                user2_result_data = {
                    'session_key': session_key,
                    'user_id': session_data['user2_id'],
                    'result_cipher': json.dumps(final_result_cipher),
                    'contact_key_cipher': json.dumps(user2_gets_contact_key),
                    'contact_encrypted': user1_contact_data['encrypted_contact']
                }
                
                # 删除可能存在的旧结果
                self.db.delete('secure_match_results', 'session_key = ?', (session_key,))
                
                # 插入新结果
                self.db.insert('secure_match_results', user1_result_data)
                self.db.insert('secure_match_results', user2_result_data)
                
                return True
                
        except Exception as e:
            logging.error(f"Compute match result error: {e}")
            return False
    
    def get_match_result(self, session_key: str, user_id: str) -> Optional[Dict[str, Any]]:
        """获取匹配结果"""
        try:
            with self.db:
                results = self.db.select('secure_match_results', 
                                       'session_key = ? AND user_id = ?', 
                                       (session_key, user_id))
                if results:
                    result_data = dict(results[0])
                    return {
                        'result_cipher': json.loads(result_data['result_cipher']),
                        'contact_key_cipher': json.loads(result_data['contact_key_cipher']),
                        'contact_encrypted': bytes.fromhex(result_data['contact_encrypted'])
                    }
                return None
                
        except Exception as e:
            logging.error(f"Get match result error: {e}")
            return None
    
    def generate_fake_result(self, shared_y: int) -> Dict[str, Any]:
        """生成虚假结果（当只有一方响应时）"""
        # 生成虚假的匹配结果密文
        fake_message = crypto_random.randrange(2, self.elgamal_params['q'])
        k = crypto_random.randrange(1, self.elgamal_params['q'])
        fake_result_cipher = (
            pow(self.elgamal_params['g'], k, self.elgamal_params['p']),
            (fake_message * pow(shared_y, k, self.elgamal_params['p'])) % self.elgamal_params['p']
        )
        
        # 生成虚假的联系方式密钥密文
        fake_key = crypto_random.randrange(1, min(2**128, self.elgamal_params['q']))
        k2 = crypto_random.randrange(1, self.elgamal_params['q'])
        fake_contact_key_cipher = (
            pow(self.elgamal_params['g'], k2, self.elgamal_params['p']),
            (fake_key * pow(shared_y, k2, self.elgamal_params['p'])) % self.elgamal_params['p']
        )
        
        # 生成虚假的联系方式密文
        fake_contact_bytes = secrets.token_bytes(32)
        
        return {
            'result_cipher': fake_result_cipher,
            'contact_key_cipher': fake_contact_key_cipher,
            'contact_encrypted': fake_contact_bytes
        }
    
    def get_user_dh_public_key(self, username: str) -> Optional[int]:
        """获取用户的DH公钥"""
        try:
            with self.db:
                account_data = self.db.select('account_data', 'username = ?', (username,))
                if account_data:
                    return int(account_data[0]['y'])
                return None
        except Exception as e:
            logging.error(f"Get user DH public key error: {e}")
            return None
    
    def cleanup_expired_sessions(self, hours: int = 24) -> int:
        """清理过期的会话"""
        try:
            import datetime
            cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
            
            with self.db:
                expired_sessions = self.db.execute_custom_sql(
                    "SELECT session_key FROM fhe_match_sessions WHERE created_at < ?",
                    (cutoff_time.isoformat(),)
                )
                
                count = 0
                for session in expired_sessions:
                    session_key = session['session_key']
                    self.db.delete('secure_match_results', 'session_key = ?', (session_key,))
                    self.db.delete('fhe_match_sessions', 'session_key = ?', (session_key,))
                    count += 1
                
                return count
                
        except Exception as e:
            logging.error(f"Cleanup expired sessions error: {e}")
            return 0