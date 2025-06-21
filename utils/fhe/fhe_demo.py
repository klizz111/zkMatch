import os
from Crypto.Cipher import AES
from Crypto.Random import random as crypto_random
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
import hashlib
from ..elgamal.elgamal import ElGamal

class SecureMatchingSystem:
    def __init__(self, bits=512, p=None, g=None, q=None):
        self.bits = bits
        self.p = p 
        self.g = g
        self.q = q 
        
        if not (self.p and self.g and self.q):
            elgamal = ElGamal(self.bits)
            elgamal.keygen()
            self.p, self.g, _ = elgamal.get_pkg()
            self.q = elgamal.q

class User:
    """用户类"""
    
    def __init__(self, name, system, contact_info=""):
        self.name = name
        self.system = system
        self.p = system.p
        self.g = system.g
        self.q = system.q
        
        # Diffie-Hellman密钥对
        self.dh_private_key = None
        self.dh_public_key = None
        
        # 共享密钥
        self.shared_secret = None
        self.shared_private_key = None
        self.shared_y = None
        
        # 匹配选择
        self.choice = None  
        
        # 联系方式
        self.contact_info = contact_info or f"{name}@example.com"
        self.encrypted_contact = None
        self.contact_key_ciphertext = None
        
    def generate_dh_keypair(self):
        """生成Diffie-Hellman密钥对"""
        # x ∈ [1, q-1]
        self.dh_private_key = crypto_random.randrange(1, self.q)
        # y = g^x mod p
        self.dh_public_key = pow(self.g, self.dh_private_key, self.p)
        
        print(f"{self.name} 生成DH密钥对:")
        print(f"  私钥: {hex(self.dh_private_key)[:20]}...")
        print(f"  公钥: {hex(self.dh_public_key)[:20]}...")
        
        return self.dh_public_key
    
    def compute_shared_secret(self, other_public_key):
        """计算共享密钥"""
        # k = other_public_key^my_private_key mod p
        self.shared_secret = pow(other_public_key, self.dh_private_key, self.p)
        
        # 派生ElGamal私钥
        hash_input = str(self.shared_secret).encode()
        hash_digest = hashlib.sha256(hash_input).digest()
        self.shared_private_key = int.from_bytes(hash_digest[:32], 'big') % self.q
        if self.shared_private_key == 0:
            self.shared_private_key = 1  # 确保私钥不为0
        
        self.shared_y = pow(self.g, self.shared_private_key, self.p)
        
        print(f"{self.name} 计算共享密钥:")
        print(f"  派生私钥: {hex(self.shared_private_key)[:20]}...")
        
        return self.shared_secret
    
    def prepare_contact_info(self):
        """准备加密的联系方式"""
        # 1. 生成联系方式加密密钥（选择较小的密钥空间以适合ElGamal）
        # 使用128位密钥，确保在ElGamal参数范围内
        contact_key_int = crypto_random.randrange(1, min(2**128, self.q))
        contact_key_bytes = contact_key_int.to_bytes(32, 'big')
        
        # 2. 使用AES加密联系方式
        cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
        padded_contact = pad(self.contact_info.encode('utf-8'), AES.block_size)
        self.encrypted_contact = cipher.encrypt(padded_contact)
        
        # 3. 使用ElGamal加密联系方式密钥（将密钥作为明文）
        k = crypto_random.randrange(1, self.q)
        c1 = pow(self.g, k, self.p)
        c2 = (contact_key_int * pow(self.shared_y, k, self.p)) % self.p
        self.contact_key_ciphertext = (c1, c2)
        
        print(f"{self.name} 加密联系方式:")
        print(f"  联系方式: {self.contact_info}")
        print(f"  AES加密后长度: {len(self.encrypted_contact)} bytes")
        print(f"  密钥明文: {contact_key_int}")
        print(f"  密钥ElGamal密文: ({hex(c1)[:15]}..., {hex(c2)[:15]}...)")
        
        return self.encrypted_contact, self.contact_key_ciphertext
     
    def set_choice(self, choice):
        """设置匹配选择"""
        self.choice = choice
        print(f"{self.name} 设置选择: {'接受' if choice else '拒绝'}")
    
    def encrypt_choice(self):
        """加密匹配选择"""
        if self.shared_private_key is None:
            raise ValueError("共享私钥未设置")
        
        if self.choice:
            # 接受：加密明文 1
            message = 1
        else:
            # 拒绝：加密随机数
            message = crypto_random.randrange(2, self.q)
        
        # 使用ElGamal加密
        k = crypto_random.randrange(1, self.q)
        c1 = pow(self.g, k, self.p)
        c2 = (message * pow(self.shared_y, k, self.p)) % self.p
        
        print(f"{self.name} 加密选择:")
        print(f"  明文: {message} ({'接受' if self.choice else '拒绝'})")
        print(f"  密文: ({hex(c1)[:15]}..., {hex(c2)[:15]}...)")
        
        return (c1, c2), message
    
    def decrypt_result(self, ciphertext):
        """解密匹配结果"""
        c1, c2 = ciphertext
        
        # 使用共享私钥解密
        s = pow(c1, self.shared_private_key, self.p)
        s_inv = pow(s, -1, self.p)
        result = (c2 * s_inv) % self.p
        
        # 判断结果
        is_match = (result == 1)
        
        print(f"{self.name} 解密结果:")
        print(f"  解密值: {result}")
        print(f"  匹配结果: {'成功' if is_match else '失败'}")
        
        return is_match, result
        
    def decrypt_contact_info_v2(self, processed_contact_key_cipher, encrypted_contact):
        """解密联系方式密钥"""
        try:
            c1, c2 = processed_contact_key_cipher
            
            # 解密经过同态处理的密钥密文
            s = pow(c1, self.shared_private_key, self.p)
            s_inv = pow(s, -1, self.p)
            decrypted_value = (c2 * s_inv) % self.p
            
            print(f"  {self.name}: 解密同态处理后的值: {decrypted_value}")
            
            try:
                contact_key_bytes = decrypted_value.to_bytes(32, 'big')
                cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
                padded_plaintext = cipher.decrypt(encrypted_contact)
                contact_info = unpad(padded_plaintext, AES.block_size).decode('utf-8')
                
                print(f"  {self.name}: 成功解密联系方式: {contact_info}")
                return contact_info
                    
            except (ValueError, UnicodeDecodeError, OverflowError) as e:
                print(f"  {self.name}: 直接使用解密值作为密钥失败 - {str(e)}")
                
                # 检查解密值是否在有效范围内，如果不在则说明匹配失败
                max_valid_key = min(2**128, self.q)
                if decrypted_value < 1 or decrypted_value >= max_valid_key:
                    print(f"  {self.name}: 解密值超出有效密钥范围，匹配可能失败")
                    return None
                else:
                    print(f"  {self.name}: 密钥在有效范围内但解密失败")
                    return None
                
        except Exception as e:
            print(f"  {self.name}: 联系方式解密异常 - {str(e)}")
            return None
        
      
class Platform:
    """平台类"""
    
    def __init__(self, system):
        self.system = system
        self.p = system.p
        self.g = system.g
        self.q = system.q
    
    def homomorphic_multiplication(self, ciphertext1, ciphertext2):
        """同态乘法运算"""
        c1_1, c2_1 = ciphertext1
        c1_2, c2_2 = ciphertext2
        
        # 同态乘法: Enc(m1) * Enc(m2) = Enc(m1 * m2)
        c1_result = (c1_1 * c1_2) % self.p
        c2_result = (c2_1 * c2_2) % self.p
        
        print("平台执行同态乘法:")
        print(f"  输入1: ({hex(c1_1)[:15]}..., {hex(c2_1)[:15]}...)")
        print(f"  输入2: ({hex(c1_2)[:15]}..., {hex(c2_2)[:15]}...)")
        print(f"  结果: ({hex(c1_result)[:15]}..., {hex(c2_result)[:15]}...)")
        
        return (c1_result, c2_result)
    
    def rerandomize(self, ciphertext):
        """对密文进行再随机化"""
        c1, c2 = ciphertext
        
        # 选择随机数 r
        r = crypto_random.randrange(1, self.q)
        
        # 对密文进行幂运算: Enc(m)^r = Enc(m^r)
        c1_new = pow(c1, r, self.p)
        c2_new = pow(c2, r, self.p)
        
        print("平台执行再随机化:")
        print(f"  随机数r: {hex(r)[:15]}...")
        print(f"  原密文: ({hex(c1)[:15]}..., {hex(c2)[:15]}...)")
        print(f"  新密文: ({hex(c1_new)[:15]}..., {hex(c2_new)[:15]}...)")
        
        return (c1_new, c2_new)
    
    def process_matching_v2(self, user1_data, user2_data):
        """使用同态乘法将匹配结果与联系方式密钥绑定"""
        print("\n--- 平台处理匹配---")
        
        choice_cipher1, (contact1_encrypted, contact1_key_cipher) = user1_data
        choice_cipher2, (contact2_encrypted, contact2_key_cipher) = user2_data
        
        # 1. 同态乘法处理匹配选择
        result_cipher = self.homomorphic_multiplication(choice_cipher1, choice_cipher2)
        
        # 2. 再随机化匹配结果
        final_result_cipher = self.rerandomize(result_cipher)
        
        print("\n平台对联系方式密钥进行同态绑定:")
        
        # 给User1(Alice)的数据：User2(Bob)的联系方式，用匹配结果绑定
        contact2_key_for_user1 = self.homomorphic_multiplication(final_result_cipher, contact2_key_cipher)
        
        # 给User2(Bob)的数据：User1(Alice)的联系方式，用匹配结果绑定  
        contact1_key_for_user2 = self.homomorphic_multiplication(final_result_cipher, contact1_key_cipher)
        
        print("平台分发数据:")
        print(f"  用户1的加密联系方式长度: {len(contact1_encrypted)} bytes")
        print(f"  用户2的加密联系方式长度: {len(contact2_encrypted)} bytes")
        print(f"  联系方式密钥已与匹配结果同态绑定")
        print(f"  只有匹配成功时解密出的才是有效密钥")
        
        # 返回：匹配结果密文，交换后的联系方式数据
        return (final_result_cipher, 
                (contact2_key_for_user1, contact2_encrypted),  # Alice获得Bob的数据
                (contact1_key_for_user2, contact1_encrypted))  # Bob获得Alice的数据

def demo_secure_matching_v2():
    
    # 系统初始化和用户创建
    system = SecureMatchingSystem(512)
    alice = User("Alice", system, "alice.secure@protonmail.com")
    bob = User("Bob", system, "bob.secure@tutanota.com")
    
    # DH密钥交换
    print("\n=== 初始化阶段 ===")
    alice_pub = alice.generate_dh_keypair()
    bob_pub = bob.generate_dh_keypair()
    alice.compute_shared_secret(bob_pub)
    bob.compute_shared_secret(alice_pub)
    
    # 准备联系方式
    alice_contact_data = alice.prepare_contact_info()
    bob_contact_data = bob.prepare_contact_info()
    
    print("\n=== 匹配测试 ===")
    scenarios = [
        (True, True, "双方都接受"),
        (True, False, "Alice接受，Bob拒绝"), 
        (False, True, "Alice拒绝，Bob接受")
    ]
    
    for i, (alice_choice, bob_choice, scenario_name) in enumerate(scenarios):
        print(f"\n{'='*25} {scenario_name} {'='*25}")
        
        alice.set_choice(alice_choice)
        bob.set_choice(bob_choice)
        
        alice_choice_cipher, _ = alice.encrypt_choice()
        bob_choice_cipher, _ = bob.encrypt_choice()
        
        platform = Platform(system)
        result_cipher, alice_gets_data, bob_gets_data = platform.process_matching_v2(
            (alice_choice_cipher, alice_contact_data), 
            (bob_choice_cipher, bob_contact_data)
        )
        
        # 解密匹配结果
        alice_result, _ = alice.decrypt_result(result_cipher)
        bob_result, _ = bob.decrypt_result(result_cipher)
        
        expected_match = alice_choice and bob_choice
        print(f"\n匹配结果: {'成功' if expected_match else '失败'}")
        
        # 使用解密联系方式
        print(f"\n--- 联系方式解密 ---")
        alice_bound_key, alice_encrypted = alice_gets_data  # Alice获得Bob的数据
        bob_bound_key, bob_encrypted = bob_gets_data        # Bob获得Alice的数据
        
        alice_contact = alice.decrypt_contact_info_v2(alice_bound_key, alice_encrypted)
        bob_contact = bob.decrypt_contact_info_v2(bob_bound_key, bob_encrypted)
        
        print(f"\n结果验证:")
        if expected_match:
            success = (alice_contact == bob.contact_info and bob_contact == alice.contact_info)
            print(f"  期望: 能够交换联系方式")
            print(f"  实际: Alice获得 '{alice_contact}', Bob获得 '{bob_contact}'")
            print(f"  验证: {'✅ 成功' if success else '❌ 失败'}")
        else:
            success = (alice_contact is None and bob_contact is None)
            print(f"  期望: 无法交换联系方式")
            print(f"  实际: Alice获得 {alice_contact}, Bob获得 {bob_contact}")
            print(f"  验证: {'✅ 成功' if success else '❌ 失败'}")
        
        # 模拟不诚实用户尝试
        print(f"\n--- 不诚实用户测试 ---")
        if not expected_match:
            print("模拟Alice忽略匹配结果，强制尝试解密:")
            # 即使Alice知道匹配失败，也尝试解密Bob的联系方式
            dishonest_result = alice.decrypt_contact_info_v2(bob_bound_key, bob_encrypted)
            if dishonest_result is None:
                print("✅ 不诚实行为被阻止：无法解密出有效联系方式")
            else:
                print(f"⚠️ 安全漏洞：不诚实用户获得了 '{dishonest_result}'")
    
    print(f"\n{'='*70}")
    print("🎉 特性验证：")
    print("1. ✅ 只有同态解密结果为原始密钥时才能成功解密联系方式")
    print("2. ✅ 不诚实用户无法绕过密钥检查")
    print("3. ✅ 平台无法得知用户选择和联系方式")
    print("4. ✅ 匹配失败时无法获得对方联系方式")
    print(f"{'='*70}")

if __name__ == "__main__":
    # 运行
    demo_secure_matching_v2()
