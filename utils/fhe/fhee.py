import random
import hashlib
from typing import Dict, Tuple, Any
import json

class FHEMatchingDemo:
    """同态加密匹配演示类"""
    
    def __init__(self):
        pass
    
    def generate_dh_keypair(self, p: int, g: int, q: int) -> Tuple[int, int]:
        """生成DH密钥对"""
        private_key = random.randint(1, q-1)
        public_key = pow(g, private_key, p)
        return private_key, public_key
    
    def compute_shared_secret(self, private_key: int, other_public_key: int, p: int) -> int:
        """计算共享密钥"""
        return pow(other_public_key, private_key, p)
    
    def prepare_contact_info(self, contact_info: str, shared_key: int, p: int, g: int) -> Dict[str, int]:
        """准备加密的联系方式"""
        # 将联系方式转换为数字
        contact_hash = int(hashlib.sha256(contact_info.encode()).hexdigest()[:16], 16)
        contact_value = contact_hash % (p - 1) + 1
        
        # 使用共享密钥加密
        r = random.randint(1, p-1)
        c1 = pow(g, r, p)
        c2 = (contact_value * pow(shared_key, r, p)) % p
        
        return {'c1': c1, 'c2': c2}
    
    def encrypt_choice(self, choice: bool, p: int, g: int, public_key: int) -> Dict[str, int]:
        """加密用户选择"""
        if choice:
            # 接受：加密明文1
            plaintext = 1
        else:
            # 拒绝：加密随机数
            plaintext = random.randint(2, p-1)
        
        # ElGamal加密
        r = random.randint(1, p-1)
        c1 = pow(g, r, p)
        c2 = (plaintext * pow(public_key, r, p)) % p
        
        return {'c1': c1, 'c2': c2}
    
    def homomorphic_multiply(self, enc1: Dict[str, int], enc2: Dict[str, int], p: int) -> Dict[str, int]:
        """同态乘法"""
        c1_result = (enc1['c1'] * enc2['c1']) % p
        c2_result = (enc1['c2'] * enc2['c2']) % p
        return {'c1': c1_result, 'c2': c2_result}
    
    def encrypt_shared_key(self, user1: str, user2: str, p: int) -> Dict[str, int]:
        """加密共享密钥标识"""
        # 创建一个基于用户名的共享密钥标识
        combined = f"{min(user1, user2)}_{max(user1, user2)}"
        key_hash = int(hashlib.sha256(combined.encode()).hexdigest()[:16], 16)
        key_value = key_hash % (p - 1) + 1
        
        # 简单加密（实际应用中需要更复杂的方案）
        r = random.randint(1, p-1)
        c1 = pow(2, r, p)  # 使用固定的g=2
        c2 = (key_value * pow(2, r, p)) % p
        
        return {'c1': c1, 'c2': c2}
    
    def decrypt_result(self, encrypted: Dict[str, int], private_key: int, p: int) -> int:
        """解密结果"""
        try:
            c1, c2 = encrypted['c1'], encrypted['c2']
            s = pow(c1, private_key, p)
            s_inv = pow(s, p-2, p)  # 模逆
            plaintext = (c2 * s_inv) % p
            return plaintext
        except:
            return 0
    
    def decrypt_contact_info(self, encrypted: Dict[str, int], shared_key: int, p: int) -> str:
        """解密联系方式"""
        try:
            c1, c2 = encrypted['c1'], encrypted['c2']
            # 计算共享密钥的r次方的逆
            s = pow(shared_key, c1, p)  # 这里需要知道r，简化处理
            s_inv = pow(s, p-2, p)
            contact_value = (c2 * s_inv) % p
            
            # 尝试恢复联系方式（这里是简化版本）
            return f"contact_{contact_value}"
        except:
            return "无法解密"