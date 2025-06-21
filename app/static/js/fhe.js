/**
 * 客户端安全匹配系统 - FHE 实现
 * 基于 ElGamal 同态加密和 Diffie-Hellman 密钥交换
 */

class SecureMatchingSystem {
    constructor(bits = 512, p = null, g = null, q = null) {
        this.bits = bits;
        this.p = p ? BigInt(p) : null;
        this.g = g ? BigInt(g) : null;
        this.q = q ? BigInt(q) : null;
        
        if (!this.p || !this.g || !this.q) {
            this.initializeSystem();
        }
    }
    
    initializeSystem() {
        // 使用预定义的安全素数参数（实际应用中应该从服务器获取）
        // 这里使用较小的参数用于演示
        this.p = BigInt("0x" + "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371");
        this.g = BigInt(2);
        this.q = (this.p - BigInt(1)) / BigInt(2);
    }
    
    setupSystem(p, g, q) {
        this.p = BigInt(p);
        this.g = BigInt(g);
        this.q = BigInt(q);
    }
}

class User {
    constructor(name, system, contactInfo = "") {
        this.name = name;
        this.system = system;
        this.p = system.p;
        this.g = system.g;
        this.q = system.q;
        
        // Diffie-Hellman 密钥对
        this.dhPrivateKey = null;
        this.dhPublicKey = null;
        
        // 共享密钥
        this.sharedSecret = null;
        this.sharedPrivateKey = null;
        this.sharedY = null;
        
        // 匹配选择
        this.choice = null;
        
        // 联系方式
        this.contactInfo = contactInfo || `${name}@secure.local`;
        this.encryptedContact = null;
        this.contactKeyCiphertext = null;
    }
    
    generateDHKeypair() {
        // 生成随机私钥 x ∈ [1, q-1]
        this.dhPrivateKey = this.randomBigInt(1n, this.q - 1n);
        // 计算公钥 y = g^x mod p
        this.dhPublicKey = this.modPow(this.g, this.dhPrivateKey, this.p);
        
        console.log(`${this.name} 生成DH密钥对:`);
        console.log(`  私钥: ${this.dhPrivateKey.toString(16).substring(0, 20)}...`);
        console.log(`  公钥: ${this.dhPublicKey.toString(16).substring(0, 20)}...`);
        
        return this.dhPublicKey;
    }
    
    computeSharedSecret(otherPublicKey) {
        // 计算共享密钥 k = other_public_key^my_private_key mod p
        this.sharedSecret = this.modPow(BigInt(otherPublicKey), this.dhPrivateKey, this.p);
        
        // 派生 ElGamal 私钥
        const hashInput = this.sharedSecret.toString();
        this.sharedPrivateKey = this.hashToBigInt(hashInput) % this.q;
        if (this.sharedPrivateKey === 0n) {
            this.sharedPrivateKey = 1n;
        }
        
        this.sharedY = this.modPow(this.g, this.sharedPrivateKey, this.p);
        
        console.log(`${this.name} 计算共享密钥:`);
        console.log(`  派生私钥: ${this.sharedPrivateKey.toString(16).substring(0, 20)}...`);
        
        return this.sharedSecret;
    }
    
    async prepareContactInfo() {
        // 生成联系方式加密密钥
        const contactKeyInt = this.randomBigInt(1n, this.q - 1n);
        const contactKeyBytes = this.bigIntToBytes(contactKeyInt, 32);
        
        // 使用 Web Crypto API 的 AES 加密联系方式
        const key = await crypto.subtle.importKey(
            'raw',
            contactKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedContact = new TextEncoder().encode(this.contactInfo);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encodedContact
        );
        
        // 将 IV 和密文合并
        this.encryptedContact = new Uint8Array(iv.length + encrypted.byteLength);
        this.encryptedContact.set(iv);
        this.encryptedContact.set(new Uint8Array(encrypted), iv.length);
        
        // 使用 ElGamal 加密联系方式密钥
        const k = this.randomBigInt(1n, this.q - 1n);
        const c1 = this.modPow(this.g, k, this.p);
        const c2 = (contactKeyInt * this.modPow(this.sharedY, k, this.p)) % this.p;
        this.contactKeyCiphertext = [c1, c2];
        
        console.log(`${this.name} 加密联系方式:`);
        console.log(`  联系方式: ${this.contactInfo}`);
        console.log(`  AES加密后长度: ${this.encryptedContact.length} bytes`);
        console.log(`  密钥明文: ${contactKeyInt.toString(16).substring(0, 15)}...`);
        console.log(`  密钥ElGamal密文: (${c1.toString(16).substring(0, 15)}..., ${c2.toString(16).substring(0, 15)}...)`);
        
        return [this.encryptedContact, this.contactKeyCiphertext];
    }
    
    setChoice(choice) {
        this.choice = choice;
        console.log(`${this.name} 设置选择: ${choice ? '接受' : '拒绝'}`);
    }
    
    encryptChoice() {
        if (this.sharedPrivateKey === null) {
            throw new Error("共享私钥未设置");
        }
        
        let message;
        if (this.choice) {
            // 接受：加密明文 1
            message = 1n;
        } else {
            // 拒绝：加密随机数（不为1）
            message = this.randomBigInt(2n, this.q - 1n);
        }
        
        // 使用 ElGamal 加密
        const k = this.randomBigInt(1n, this.q - 1n);
        const c1 = this.modPow(this.g, k, this.p);
        const c2 = (message * this.modPow(this.sharedY, k, this.p)) % this.p;
        
        console.log(`${this.name} 加密选择:`);
        console.log(`  明文: ${message} (${this.choice ? '接受' : '拒绝'})`);
        console.log(`  密文: (${c1.toString(16).substring(0, 15)}..., ${c2.toString(16).substring(0, 15)}...)`);
        
        return [[c1, c2], message];
    }
    
    decryptResult(ciphertext) {
        const [c1, c2] = ciphertext.map(x => BigInt(x));
        
        // 使用共享私钥解密
        const s = this.modPow(c1, this.sharedPrivateKey, this.p);
        const sInv = this.modInverse(s, this.p);
        const result = (c2 * sInv) % this.p;
        
        // 判断结果
        const isMatch = result === 1n;
        
        console.log(`${this.name} 解密结果:`);
        console.log(`  解密值: ${result}`);
        console.log(`  匹配结果: ${isMatch ? '成功' : '失败'}`);
        
        return [isMatch, result];
    }
    
    async decryptContactInfo(processedContactKeyCipher, encryptedContact) {
        try {
            const [c1, c2] = processedContactKeyCipher.map(x => BigInt(x));
            
            // 解密经过同态处理的密钥密文
            const s = this.modPow(c1, this.sharedPrivateKey, this.p);
            const sInv = this.modInverse(s, this.p);
            const decryptedValue = (c2 * sInv) % this.p;
            
            console.log(`  ${this.name}: 解密同态处理后的值: ${decryptedValue}`);
            
            try {
                const contactKeyBytes = this.bigIntToBytes(decryptedValue, 32);
                
                // 分离 IV 和密文
                const iv = encryptedContact.slice(0, 12);
                const ciphertext = encryptedContact.slice(12);
                
                // 导入密钥
                const key = await crypto.subtle.importKey(
                    'raw',
                    contactKeyBytes,
                    { name: 'AES-GCM' },
                    false,
                    ['decrypt']
                );
                
                // 解密
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    ciphertext
                );
                
                const contactInfo = new TextDecoder().decode(decrypted);
                
                console.log(`  ${this.name}: 成功解密联系方式: ${contactInfo}`);
                return contactInfo;
                
            } catch (e) {
                console.log(`  ${this.name}: 解密失败 - ${e.message}`);
                
                // 检查解密值是否在有效范围内
                const maxValidKey = this.q;
                if (decryptedValue < 1n || decryptedValue >= maxValidKey) {
                    console.log(`  ${this.name}: 解密值超出有效密钥范围，匹配可能失败`);
                    return null;
                } else {
                    console.log(`  ${this.name}: 密钥在有效范围内但解密失败`);
                    return null;
                }
            }
            
        } catch (e) {
            console.log(`  ${this.name}: 联系方式解密异常 - ${e.message}`);
            return null;
        }
    }
    
    // 辅助方法
    randomBigInt(min, max) {
        const range = max - min;
        const bits = range.toString(2).length;
        let result;
        do {
            result = 0n;
            for (let i = 0; i < bits; i++) {
                result = result * 2n + BigInt(Math.floor(Math.random() * 2));
            }
            result = result + min;
        } while (result >= max);
        return result;
    }
    
    modPow(base, exponent, modulus) {
        let result = 1n;
        base = base % modulus;
        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1n;
            base = (base * base) % modulus;
        }
        return result;
    }
    
    modInverse(a, m) {
        const [gcd, x] = this.extendedGCD(a, m);
        if (gcd !== 1n) {
            throw new Error('Modular inverse does not exist');
        }
        return ((x % m) + m) % m;
    }
    
    extendedGCD(a, b) {
        if (a === 0n) {
            return [b, 0n, 1n];
        }
        const [gcd, x1, y1] = this.extendedGCD(b % a, a);
        const x = y1 - (b / a) * x1;
        const y = x1;
        return [gcd, x, y];
    }
    
    hashToBigInt(input) {
        // 简单的哈希函数（实际应用中应使用更安全的方法）
        let hash = 0n;
        for (let i = 0; i < input.length; i++) {
            hash = (hash * 31n + BigInt(input.charCodeAt(i))) % this.q;
        }
        return hash;
    }
    
    bigIntToBytes(bigint, length) {
        const hex = bigint.toString(16).padStart(length * 2, '0');
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }
}

class Platform {
    constructor(system) {
        this.system = system;
        this.p = system.p;
        this.g = system.g;
        this.q = system.q;
    }
    
    homomorphicMultiplication(ciphertext1, ciphertext2) {
        const [c1_1, c2_1] = ciphertext1.map(x => BigInt(x));
        const [c1_2, c2_2] = ciphertext2.map(x => BigInt(x));
        
        // 同态乘法: Enc(m1) * Enc(m2) = Enc(m1 * m2)
        const c1Result = (c1_1 * c1_2) % this.p;
        const c2Result = (c2_1 * c2_2) % this.p;
        
        console.log("平台执行同态乘法:");
        console.log(`  输入1: (${c1_1.toString(16).substring(0, 15)}..., ${c2_1.toString(16).substring(0, 15)}...)`);
        console.log(`  输入2: (${c1_2.toString(16).substring(0, 15)}..., ${c2_2.toString(16).substring(0, 15)}...)`);
        console.log(`  结果: (${c1Result.toString(16).substring(0, 15)}..., ${c2Result.toString(16).substring(0, 15)}...)`);
        
        return [c1Result, c2Result];
    }
    
    rerandomize(ciphertext) {
        const [c1, c2] = ciphertext.map(x => BigInt(x));
        
        // 选择随机数 r
        const r = this.randomBigInt(1n, this.q - 1n);
        
        // 对密文进行幂运算: Enc(m)^r = Enc(m^r)
        const c1New = this.modPow(c1, r, this.p);
        const c2New = this.modPow(c2, r, this.p);
        
        console.log("平台执行再随机化:");
        console.log(`  随机数r: ${r.toString(16).substring(0, 15)}...`);
        console.log(`  原密文: (${c1.toString(16).substring(0, 15)}..., ${c2.toString(16).substring(0, 15)}...)`);
        console.log(`  新密文: (${c1New.toString(16).substring(0, 15)}..., ${c2New.toString(16).substring(0, 15)}...)`);
        
        return [c1New, c2New];
    }
    
    processSecureMatching(user1Data, user2Data) {
        console.log("\n--- 平台处理匹配 ---");
        
        const [choiceCipher1, [contact1Encrypted, contact1KeyCipher]] = user1Data;
        const [choiceCipher2, [contact2Encrypted, contact2KeyCipher]] = user2Data;
        
        // 1. 同态乘法处理匹配选择
        const resultCipher = this.homomorphicMultiplication(choiceCipher1, choiceCipher2);
        
        // 2. 再随机化匹配结果
        const finalResultCipher = this.rerandomize(resultCipher);
        
        console.log("\n平台对联系方式密钥进行同态绑定:");
        
        // 给User1的数据：User2的联系方式，用匹配结果绑定
        const contact2KeyForUser1 = this.homomorphicMultiplication(finalResultCipher, contact2KeyCipher);
        
        // 给User2的数据：User1的联系方式，用匹配结果绑定
        const contact1KeyForUser2 = this.homomorphicMultiplication(finalResultCipher, contact1KeyCipher);
        
        console.log("平台分发数据:");
        console.log(`  用户1的加密联系方式长度: ${contact1Encrypted.length} bytes`);
        console.log(`  用户2的加密联系方式长度: ${contact2Encrypted.length} bytes`);
        console.log(`  联系方式密钥已与匹配结果同态绑定`);
        console.log(`  只有匹配成功时解密出的才是有效密钥`);
        
        // 返回：匹配结果密文，交换后的联系方式数据
        return [
            finalResultCipher,
            [contact2KeyForUser1, contact2Encrypted],  // User1获得User2的数据
            [contact1KeyForUser2, contact1Encrypted]   // User2获得User1的数据
        ];
    }
    
    // 辅助方法
    randomBigInt(min, max) {
        const range = max - min;
        const bits = range.toString(2).length;
        let result;
        do {
            result = 0n;
            for (let i = 0; i < bits; i++) {
                result = result * 2n + BigInt(Math.floor(Math.random() * 2));
            }
            result = result + min;
        } while (result >= max);
        return result;
    }
    
    modPow(base, exponent, modulus) {
        let result = 1n;
        base = base % modulus;
        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1n;
            base = (base * base) % modulus;
        }
        return result;
    }
}

// 安全匹配管理器
class SecureMatchingManager {
    constructor() {
        this.system = null;
        this.currentUser = null;
        this.platform = null;
        this.sessions = new Map(); // 存储匹配会话
    }
    
    async initializeSystem(systemParams = null) {
        if (systemParams) {
            this.system = new SecureMatchingSystem(512, systemParams.p, systemParams.g, systemParams.q);
        } else {
            this.system = new SecureMatchingSystem(512);
        }
        this.platform = new Platform(this.system);
        console.log("安全匹配系统初始化完成");
    }
    
    createUser(username, contactInfo) {
        const user = new User(username, this.system, contactInfo);
        console.log(`创建用户: ${username}`);
        return user;
    }
    
    async createMatchingSession(user1, user2) {
        // 生成DH密钥对
        const user1Pub = user1.generateDHKeypair();
        const user2Pub = user2.generateDHKeypair();
        
        // 交换公钥并计算共享密钥
        user1.computeSharedSecret(user2Pub);
        user2.computeSharedSecret(user1Pub);
        
        // 准备联系方式
        const user1ContactData = await user1.prepareContactInfo();
        const user2ContactData = await user2.prepareContactInfo();
        
        const sessionKey = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        this.sessions.set(sessionKey, {
            user1,
            user2,
            user1ContactData,
            user2ContactData,
            created: new Date()
        });
        
        console.log(`创建匹配会话: ${sessionKey}`);
        return sessionKey;
    }
    
    async processMatching(sessionKey, user1Choice, user2Choice) {
        const session = this.sessions.get(sessionKey);
        if (!session) {
            throw new Error("会话不存在");
        }
        
        const { user1, user2, user1ContactData, user2ContactData } = session;
        
        // 设置选择并加密
        user1.setChoice(user1Choice);
        user2.setChoice(user2Choice);
        
        const [user1ChoiceCipher] = user1.encryptChoice();
        const [user2ChoiceCipher] = user2.encryptChoice();
        
        // 平台处理
        const [resultCipher, user1GetsData, user2GetsData] = this.platform.processSecureMatching(
            [user1ChoiceCipher, user1ContactData],
            [user2ChoiceCipher, user2ContactData]
        );
        
        // 解密匹配结果
        const [user1Result] = user1.decryptResult(resultCipher);
        const [user2Result] = user2.decryptResult(resultCipher);
        
        const isMatch = user1Result && user2Result;
        
        // 解密联系方式（如果匹配成功）
        let user1Contact = null;
        let user2Contact = null;
        
        if (isMatch) {
            user1Contact = await user1.decryptContactInfo(user1GetsData[0], user1GetsData[1]);
            user2Contact = await user2.decryptContactInfo(user2GetsData[0], user2GetsData[1]);
        }
        
        return {
            sessionKey,
            isMatch,
            user1Result,
            user2Result,
            user1Contact,
            user2Contact
        };
    }
    
    getSystemParams() {
        return {
            p: this.system.p.toString(),
            g: this.system.g.toString(),
            q: this.system.q.toString()
        };
    }
}

// 导出类供其他模块使用
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SecureMatchingSystem,
        User,
        Platform,
        SecureMatchingManager
    };
} else {
    // 浏览器环境
    window.SecureMatchingSystem = SecureMatchingSystem;
    window.User = User;
    window.Platform = Platform;
    window.SecureMatchingManager = SecureMatchingManager;
}