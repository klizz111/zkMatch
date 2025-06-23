// FHE同态加密匹配系统的JavaScript实现
class FHEMatching {
    constructor() {
        this.systemParams = null;
        this.dhPrivateKey = null;
        this.dhPublicKey = null;
        this.currentSessions = new Map(); // 存储当前会话的共享密钥信息
    }

    // 初始化系统参数
    async init() {
        try {
            const response = await fetch('/api/system_params');
            const data = await response.json();
            
            if (data.success) {
                this.systemParams = {
                    p: BigInt(data.params.p),
                    g: BigInt(data.params.g),
                    q: BigInt(data.params.q)
                };
                console.log('FHE系统参数初始化成功');
                return true;
            } else {
                throw new Error(data.error || '获取系统参数失败');
            }
        } catch (error) {
            console.error('FHE系统初始化失败:', error);
            throw error;
        }
    }

    // 生成Diffie-Hellman密钥对
    generateDHKeypair() {
        if (!this.systemParams) {
            throw new Error('系统参数未初始化');
        }

        // 生成私钥：x ∈ [1, q-1]
        this.dhPrivateKey = this.randomBigInt(1n, this.systemParams.q - 1n);
        
        // 计算公钥：y = g^x mod p
        this.dhPublicKey = this.modPow(this.systemParams.g, this.dhPrivateKey, this.systemParams.p);
        
        console.log('DH密钥对生成成功');
        return this.dhPublicKey;
    }

    // 计算共享密钥
    computeSharedSecret(otherPublicKey, sessionKey) {
        if (!this.dhPrivateKey) {
            throw new Error('DH私钥未生成');
        }

        const otherPubKeyBigInt = BigInt(otherPublicKey);
        
        // 计算共享秘密：shared_secret = other_public_key^my_private_key mod p
        const sharedSecret = this.modPow(otherPubKeyBigInt, this.dhPrivateKey, this.systemParams.p);
        
        // 派生ElGamal私钥
        const hashInput = sharedSecret.toString();
        const hashDigest = this.sha256(hashInput);
        let sharedPrivateKey = BigInt('0x' + hashDigest) % this.systemParams.q;
        if (sharedPrivateKey === 0n) {
            sharedPrivateKey = 1n;
        }
        
        // 计算共享公钥：shared_y = g^shared_private_key mod p
        const sharedY = this.modPow(this.systemParams.g, sharedPrivateKey, this.systemParams.p);
        
        // 存储会话信息
        this.currentSessions.set(sessionKey, {
            sharedSecret,
            sharedPrivateKey,
            sharedY
        });
        
        console.log(`会话 ${sessionKey} 的共享密钥计算完成`);
        return { sharedSecret, sharedPrivateKey, sharedY };
    }

    // 准备加密的联系方式
    async prepareContactInfo(contactInfo, sessionKey) {
        const sessionData = this.currentSessions.get(sessionKey);
        if (!sessionData) {
            throw new Error('会话数据不存在');
        }

        // 生成联系方式加密密钥（128位，确保在ElGamal参数范围内）
        const maxKey = 2n ** 128n < this.systemParams.q ? 2n ** 128n : this.systemParams.q;
        const contactKeyInt = this.randomBigInt(1n, maxKey - 1n);
        
        // 使用Web Crypto API进行AES加密
        const contactKeyBytes = this.bigIntToBytes(contactKeyInt, 32);
        const key = await crypto.subtle.importKey(
            'raw',
            contactKeyBytes,
            { name: 'AES-ECB' },
            false,
            ['encrypt']
        );
        
        const encoder = new TextEncoder();
        const contactBytes = encoder.encode(contactInfo);
        
        // 填充到16字节的倍数
        const paddedContact = this.pkcs7Pad(contactBytes, 16);
        const encryptedContact = await crypto.subtle.encrypt(
            { name: 'AES-ECB' },
            key,
            paddedContact
        );
        
        // 使用ElGamal加密联系方式密钥
        const k = this.randomBigInt(1n, this.systemParams.q - 1n);
        const c1 = this.modPow(this.systemParams.g, k, this.systemParams.p);
        const c2 = (contactKeyInt * this.modPow(sessionData.sharedY, k, this.systemParams.p)) % this.systemParams.p;
        
        console.log('联系方式加密完成');
        return {
            encrypted_contact: Array.from(new Uint8Array(encryptedContact)).map(b => b.toString(16).padStart(2, '0')).join(''),
            contact_key_cipher: [c1.toString(), c2.toString()]
        };
    }

    // 加密用户选择
    encryptChoice(choice, sessionKey) {
        const sessionData = this.currentSessions.get(sessionKey);
        if (!sessionData) {
            throw new Error('会话数据不存在');
        }

        let message;
        if (choice) {
            message = 1n; // 接受
        } else {
            message = this.randomBigInt(2n, this.systemParams.q - 1n); // 拒绝：随机数
        }

        // 使用ElGamal加密
        const k = this.randomBigInt(1n, this.systemParams.q - 1n);
        const c1 = this.modPow(this.systemParams.g, k, this.systemParams.p);
        const c2 = (message * this.modPow(sessionData.sharedY, k, this.systemParams.p)) % this.systemParams.p;

        console.log(`选择加密完成: ${choice ? '接受' : '拒绝'}`);
        return [c1.toString(), c2.toString()];
    }

    // 解密匹配结果
    decryptResult(resultCipher, sessionKey) {
        const sessionData = this.currentSessions.get(sessionKey);
        if (!sessionData) {
            throw new Error('会话数据不存在');
        }

        const c1 = BigInt(resultCipher[0]);
        const c2 = BigInt(resultCipher[1]);

        // 解密：result = c2 * (c1^shared_private_key)^(-1) mod p
        const s = this.modPow(c1, sessionData.sharedPrivateKey, this.systemParams.p);
        const sInv = this.modInverse(s, this.systemParams.p);
        const result = (c2 * sInv) % this.systemParams.p;

        const isMatch = result === 1n;
        console.log(`匹配结果解密: ${isMatch ? '成功' : '失败'} (${result})`);
        return { isMatch, result: result.toString() };
    }

    // 解密联系方式
    async decryptContactInfo(contactKeyCipher, encryptedContactHex, sessionKey) {
        try {
            const sessionData = this.currentSessions.get(sessionKey);
            if (!sessionData) {
                throw new Error('会话数据不存在');
            }

            const c1 = BigInt(contactKeyCipher[0]);
            const c2 = BigInt(contactKeyCipher[1]);

            // 解密联系方式密钥
            const s = this.modPow(c1, sessionData.sharedPrivateKey, this.systemParams.p);
            const sInv = this.modInverse(s, this.systemParams.p);
            const decryptedValue = (c2 * sInv) % this.systemParams.p;

            try {
                // 将解密值转换为AES密钥
                const contactKeyBytes = this.bigIntToBytes(decryptedValue, 32);
                
                const key = await crypto.subtle.importKey(
                    'raw',
                    contactKeyBytes,
                    { name: 'AES-ECB' },
                    false,
                    ['decrypt']
                );

                // 解密联系方式
                const encryptedContact = new Uint8Array(
                    encryptedContactHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
                );

                const decryptedPadded = await crypto.subtle.decrypt(
                    { name: 'AES-ECB' },
                    key,
                    encryptedContact
                );

                // 去除填充
                const decryptedBytes = this.pkcs7Unpad(new Uint8Array(decryptedPadded));
                const decoder = new TextDecoder();
                const contactInfo = decoder.decode(decryptedBytes);

                console.log('联系方式解密成功:', contactInfo);
                return contactInfo;

            } catch (error) {
                console.log('联系方式解密失败 - 可能匹配失败:', error.message);
                return null;
            }

        } catch (error) {
            console.error('联系方式解密异常:', error);
            return null;
        }
    }

    // 提交选择到服务器
    async submitChoice(sessionKey, choice, contactInfo) {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            // 准备加密数据
            const contactData = await this.prepareContactInfo(contactInfo, sessionKey);
            const choiceCipher = this.encryptChoice(choice, sessionKey);

            const response = await fetch('/api/submit_choice', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`
                },
                body: JSON.stringify({
                    session_key: sessionKey,
                    choice_cipher: choiceCipher,
                    contact_data: contactData
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '提交选择失败');
            }

            const result = await response.json();
            console.log('选择提交成功');
            return result;

        } catch (error) {
            console.error('提交选择失败:', error);
            throw error;
        }
    }

    // 获取匹配结果
    async getMatchResult(sessionKey) {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            const response = await fetch(`/api/get_match_result?session_key=${sessionKey}`, {
                headers: {
                    'Authorization': `Bearer ${sessionId}`
                }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '获取匹配结果失败');
            }

            const data = await response.json();
            console.log('匹配结果获取成功:', data.result_computed ? '真实结果' : '临时结果');
            return data;

        } catch (error) {
            console.error('获取匹配结果失败:', error);
            throw error;
        }
    }

    // 保存匹配结果
    async saveMatchResult(sessionKey, isMatch, contactInfo = null) {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            const response = await fetch('/api/save_match_result', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`
                },
                body: JSON.stringify({
                    session_key: sessionKey,
                    is_match: isMatch,
                    contact_info: contactInfo
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '保存匹配结果失败');
            }

            return await response.json();

        } catch (error) {
            console.error('保存匹配结果失败:', error);
            throw error;
        }
    }

    // 辅助方法：生成随机BigInt
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

    // 辅助方法：模幂运算
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

    // 辅助方法：模逆运算
    modInverse(a, m) {
        const extendedGCD = (a, b) => {
            if (a === 0n) return [b, 0n, 1n];
            const [gcd, x1, y1] = extendedGCD(b % a, a);
            const x = y1 - (b / a) * x1;
            const y = x1;
            return [gcd, x, y];
        };

        const [gcd, x] = extendedGCD(a % m, m);
        if (gcd !== 1n) {
            throw new Error('模逆不存在');
        }
        return (x % m + m) % m;
    }

    // 辅助方法：BigInt转字节数组
    bigIntToBytes(bigint, length) {
        const hex = bigint.toString(16).padStart(length * 2, '0');
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }

    // 辅助方法：PKCS7填充
    pkcs7Pad(data, blockSize) {
        const padLength = blockSize - (data.length % blockSize);
        const padded = new Uint8Array(data.length + padLength);
        padded.set(data);
        for (let i = data.length; i < padded.length; i++) {
            padded[i] = padLength;
        }
        return padded;
    }

    // 辅助方法：PKCS7去填充
    pkcs7Unpad(data) {
        const padLength = data[data.length - 1];
        return data.slice(0, data.length - padLength);
    }

    // 辅助方法：简单SHA256（用于演示）
    sha256(message) {
        // 这是一个简化的实现，实际应用中应使用Web Crypto API
        let hash = 0;
        for (let i = 0; i < message.length; i++) {
            const char = message.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // 转换为32位整数
        }
        return Math.abs(hash).toString(16).padStart(64, '0');
    }
}

// 全局FHE匹配实例
window.fheMatching = new FHEMatching();