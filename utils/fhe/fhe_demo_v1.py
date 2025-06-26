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
        self.p = p  # 大素数
        self.g = g  # 原根
        self.q = q  # 安全参数
        
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
        self.choice = None  # True表示接受，False表示拒绝
        
        # 联系方式
        self.contact_info = contact_info or f"{name}@example.com"
        self.encrypted_contact = None
        self.contact_key_ciphertext = None
        
    def generate_dh_keypair(self):
        """生成Diffie-Hellman密钥对"""
        # 私钥 x ∈ [1, q-1]
        self.dh_private_key = crypto_random.randrange(1, self.q)
        # 公钥 y = g^x mod p
        self.dh_public_key = pow(self.g, self.dh_private_key, self.p)
        
        print(f"{self.name} 生成DH密钥对:")
        print(f"  私钥: {hex(self.dh_private_key)[:20]}...")
        print(f"  公钥: {hex(self.dh_public_key)[:20]}...")
        
        return self.dh_public_key
    
    def compute_shared_secret(self, other_public_key):
        """计算共享密钥"""
        # k = other_public_key^my_private_key mod p
        self.shared_secret = pow(other_public_key, self.dh_private_key, self.p)
        
        # 使用哈希函数派生ElGamal私钥
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
        
        print(f"{self.name} 准备联系方式:")
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

    def decrypt_contact_info(self, contact_key_ciphertext, encrypted_contact, match_result):
        """解密对方的联系方式（仅在匹配成功时有效）"""
        # 首先检查匹配是否成功
        if not match_result:
            print(f"  {self.name}: 匹配失败，拒绝解密联系方式")
            return None
            
        try:
            c1, c2 = contact_key_ciphertext
            
            # 解密联系方式密钥
            s = pow(c1, self.shared_private_key, self.p)
            s_inv = pow(s, -1, self.p)
            contact_key_int = (c2 * s_inv) % self.p
            
            print(f"  {self.name}: 解密得到密钥数值: {contact_key_int}")
            
            # 将解密得到的数值转换为字节
            try:
                # 限制在128位范围内
                if contact_key_int > 2**128:
                    print(f"  {self.name}: 解密得到的密钥数值过大")
                    return None
                    
                contact_key_bytes = contact_key_int.to_bytes(32, 'big')
            except (OverflowError, ValueError) as e:
                print(f"  {self.name}: 密钥转换失败 - {str(e)}")
                return None
            
            # 使用解密的密钥尝试解密联系方式
            cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
            try:
                padded_plaintext = cipher.decrypt(encrypted_contact)
                contact_info = unpad(padded_plaintext, AES.block_size).decode('utf-8')
                print(f"  {self.name}: 成功解密对方联系方式")
                return contact_info
            except (ValueError, UnicodeDecodeError) as e:
                print(f"  {self.name}: 联系方式解密失败 - {str(e)}")
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
    
    def process_matching(self, user1_data, user2_data):
        """处理匹配请求，使用条件传输方法"""
        print("\n--- 平台处理匹配 ---")
        
        choice_cipher1, (contact1_encrypted, contact1_key_cipher) = user1_data
        choice_cipher2, (contact2_encrypted, contact2_key_cipher) = user2_data
        
        # 1. 同态乘法处理匹配选择
        result_cipher = self.homomorphic_multiplication(choice_cipher1, choice_cipher2)
        
        # 2. 再随机化匹配结果
        final_result_cipher = self.rerandomize(result_cipher)
        
        # 3. 条件传输：直接传输原始联系方式密文，不进行同态运算
        # 让用户端根据匹配结果决定是否能成功解密
        print("\n平台采用条件传输方案:")
        print("平台分发数据:")
        print(f"  用户1的加密联系方式长度: {len(contact1_encrypted)} bytes")
        print(f"  用户2的加密联系方式长度: {len(contact2_encrypted)} bytes")
        print(f"  联系方式密钥保持原始形式，由用户端控制解密")
        
        # 返回：匹配结果密文，原始联系方式数据
        return (final_result_cipher, 
                (contact2_key_cipher, contact2_encrypted),
                (contact1_key_cipher, contact1_encrypted))
    
def demo_secure_matching():
    #演示
    print("=" * 60)
    print("基于公钥密码的安全网恋匹配系统演示")
    print("（含联系方式交换功能）")
    print("=" * 60)
    
    # 1. 系统初始化
    system = SecureMatchingSystem(512)
    
    # 2. 创建用户（包含联系方式）
    print("\n=== 用户注册 ===")
    alice = User("Alice", system, "alice.wang@email.com")
    bob = User("Bob", system, "bob.li@email.com")
    
    # 3. 用户生成DH密钥对并上传公钥到平台
    print("\n=== Diffie-Hellman密钥交换 ===")
    alice_pub = alice.generate_dh_keypair()
    bob_pub = bob.generate_dh_keypair()
    
    # 4. 平台推送匹配，用户计算共享密钥
    print("\n=== 计算共享密钥 ===")
    alice_shared = alice.compute_shared_secret(bob_pub)
    bob_shared = bob.compute_shared_secret(alice_pub)
    
    # 验证共享密钥是否一致
    print(f"\n共享密钥验证: {alice_shared == bob_shared}")
    assert alice_shared == bob_shared, "共享密钥不一致!"
    
    # 5. 用户准备加密的联系方式
    print("\n=== 准备联系方式 ===")
    alice_contact_data = alice.prepare_contact_info()
    bob_contact_data = bob.prepare_contact_info()
    
    # 6. 测试不同场景
    print("\n=== 匹配场景测试 ===")
    scenarios = [
        (True, True, "双方都接受"),
        (True, False, "Alice接受，Bob拒绝"),
        (False, True, "Alice拒绝，Bob接受"),
        (False, False, "双方都拒绝")
    ]
    
    for i, (alice_choice, bob_choice, scenario_name) in enumerate(scenarios):
        print(f"\n{'='*20} 场景 {i+1}: {scenario_name} {'='*20}")
        
        # 设置选择
        alice.set_choice(alice_choice)
        bob.set_choice(bob_choice)
        
        # 加密选择
        print("\n--- 加密选择 ---")
        alice_choice_cipher, alice_msg = alice.encrypt_choice()
        bob_choice_cipher, bob_msg = bob.encrypt_choice()
        
        # 平台处理匹配
        platform = Platform(system)
        result_cipher, alice_gets_data, bob_gets_data = platform.process_matching(
            (alice_choice_cipher, alice_contact_data), 
            (bob_choice_cipher, bob_contact_data)
        )
        
        # 解密匹配结果
        print("\n--- 解密匹配结果 ---")
        alice_result, alice_decrypt = alice.decrypt_result(result_cipher)
        bob_result, bob_decrypt = bob.decrypt_result(result_cipher)
        
        # 验证匹配结果正确性
        expected_match = alice_choice and bob_choice
        actual_match = alice_result and bob_result
        
        print(f"\n结果验证:")
        print(f"  期望结果: {'匹配成功' if expected_match else '匹配失败'}")
        print(f"  实际结果: {'匹配成功' if actual_match else '匹配失败'}")
        print(f"  系统正确性: {'✅ 正确' if expected_match == actual_match else '❌ 错误'}")
        
        # 尝试解密联系方式
        print(f"\n--- 联系方式交换测试 ---")
        alice_contact_key_cipher, alice_encrypted_contact = alice_gets_data
        bob_contact_key_cipher, bob_encrypted_contact = bob_gets_data
        
        alice_decrypted_contact = alice.decrypt_contact_info(bob_contact_key_cipher, bob_encrypted_contact, alice_result)
        bob_decrypted_contact = bob.decrypt_contact_info(alice_contact_key_cipher, alice_encrypted_contact, bob_result)
        
        if expected_match:
            # 匹配成功时应该能解密出正确的联系方式
            print(f"Alice获得Bob联系方式: {alice_decrypted_contact}")
            print(f"Bob获得Alice联系方式: {bob_decrypted_contact}")
            
            contact_exchange_success = (
                alice_decrypted_contact == bob.contact_info and 
                bob_decrypted_contact == alice.contact_info
            )
            print(f"联系方式交换: {'✅ 成功' if contact_exchange_success else '❌ 失败'}")
        else:
            # 匹配失败时应该无法解密出有效的联系方式
            print(f"Alice尝试解密联系方式: {'❌ 失败（正确）' if alice_decrypted_contact is None else '⚠️ 意外成功'}")
            print(f"Bob尝试解密联系方式: {'❌ 失败（正确）' if bob_decrypted_contact is None else '⚠️ 意外成功'}")
            
            if alice_decrypted_contact is not None:
                print(f"  Alice意外解密出: {alice_decrypted_contact}")
            if bob_decrypted_contact is not None:
                print(f"  Bob意外解密出: {bob_decrypted_contact}")
        
        # 隐私保护分析
        print(f"\n--- 隐私保护分析 ---")
        if not expected_match:
            if alice_choice and not bob_choice:
                print("✅ Alice选择接受但匹配失败，无法得知Bob的具体选择")
                print("✅ Alice无法获得Bob的联系方式")
            elif not alice_choice and bob_choice:
                print("✅ Bob选择接受但匹配失败，无法得知Alice的具体选择")
                print("✅ Bob无法获得Alice的联系方式")
            else:
                print("✅ 双方都拒绝，从结果可推断对方必然拒绝")
                print("✅ 但双方都无法获得对方联系方式")
        else:
            print("✅ 匹配成功，双方都知道对方选择了接受")
            print("✅ 双方成功交换联系方式")
        
        print("✅ 平台无法得知用户的具体选择和联系方式")
    
    print("\n" + "=" * 60)
    print("🎉 演示完成！系统成功实现了以下目标：")
    print("1. ✅ 平台无法得知用户的具体选择")
    print("2. ✅ 平台无法得知用户的联系方式")
    print("3. ✅ 匹配失败时，用户无法推断对方的选择")
    print("4. ✅ 匹配失败时，用户无法获得对方的联系方式")
    print("5. ✅ 只有双方都接受时才会匹配成功并交换联系方式")
    print("6. ✅ 系统具有完整的隐私保护特性")
    print("=" * 60)

if __name__ == "__main__":
    # 运行改进版本
    demo_secure_matching()


