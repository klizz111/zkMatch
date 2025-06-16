// 安全的ElGamal实现 - 支持零知识证明登录
class SecureElGamal {
    constructor(bits) {
        this.bits = bits;
        this.p = null;
        this.g = null;
        this.y = null;
        this.x = null;
        this.q = null;
    }
    
    // 客户端生成密码/种子
    generateSeed() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    // 用户注册 - 第一步：发送到服务端生成公钥参数
    async register(username, seed) {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                seed_hash: await this.hashSeed(seed),
                bits: this.bits
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || '注册失败');
        }
        
        const data = await response.json();
        this.p = BigInt(data.p);
        this.g = BigInt(data.g);
        this.q = BigInt(data.q);
        
        // 客户端本地生成私钥
        this.x = await this.derivePrivateKey(seed);
        this.y = this.modPow(this.g, this.x, this.p);
        
        // 第二步：发送公钥完成注册
        return await this.completeRegistration(username);
    }
    
    // 完成注册 - 第二步：发送公钥到服务器
    async completeRegistration(username) {
        const response = await fetch('/api/complete_registration', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                y: this.y.toString()
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || '完成注册失败');
        }
        
        const data = await response.json();
        return {
            success: true,
            login_token: data.login_token,
            public_key: {
                p: this.p.toString(),
                g: this.g.toString(),
                y: this.y.toString()
            }
        };
    }
    
    // 零知识证明登录
    async zkLogin(username, seed, loginToken = '') {
        try {
            // 第一步：获取登录挑战
            const challengeResponse = await fetch('/api/login_challenge', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    login_token: loginToken
                })
            });
            
            if (!challengeResponse.ok) {
                const error = await challengeResponse.json();
                throw new Error(error.error || '获取登录挑战失败');
            }
            
            const challengeData = await challengeResponse.json();
            
            // 设置公钥参数
            this.p = BigInt(challengeData.p);
            this.g = BigInt(challengeData.g);
            this.y = BigInt(challengeData.y);
            this.q = (this.p - 1n) / 2n;
            
            // 获取私钥：优先使用种子派生，否则从本地存储获取
            if (seed) {
                this.x = await this.derivePrivateKey(seed);
                // 保存到本地存储以供快速登录使用
                this.savePrivateKeyToLocal(username, this.x);
            } else if (loginToken) {
                // 快速登录：从本地存储获取私钥
                this.x = this.getPrivateKeyFromLocal(username);
                if (!this.x) {
                    throw new Error('未找到本地保存的私钥。请使用完整登录重新验证身份。');
                }
            } else {
                throw new Error('需要密码种子或有效的登录令牌');
            }
            
            // 生成零知识证明
            const proof = await this.generateDLogProof();
            
            // 第二步：发送证明进行验证
            const verifyResponse = await fetch('/api/login_verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    proof_c: proof.c.toString(),
                    proof_z: proof.z.toString()
                })
            });
            
            if (!verifyResponse.ok) {
                const error = await verifyResponse.json();
                throw new Error(error.error || '登录验证失败');
            }
            
            const verifyData = await verifyResponse.json();
            return {
                success: true,
                message: verifyData.message,
                user_info: verifyData.user_info
            };
            
        } catch (error) {
            throw new Error(`登录失败: ${error.message}`);
        }
    }
    
    // 保存私钥到本地存储（加密保存）
    savePrivateKeyToLocal(username, privateKey) {
        try {
            const keyData = {
                username: username,
                privateKey: privateKey.toString(),
                timestamp: Date.now()
            };
            
            // 简单的混淆（实际应用中应使用更强的加密）
            const encodedData = btoa(JSON.stringify(keyData));
            localStorage.setItem(`zk_key_${username}`, encodedData);
        } catch (error) {
            console.warn('无法保存私钥到本地存储:', error);
        }
    }
    
    // 从本地存储获取私钥
    getPrivateKeyFromLocal(username) {
        try {
            const encodedData = localStorage.getItem(`zk_key_${username}`);
            if (!encodedData) return null;
            
            const keyData = JSON.parse(atob(encodedData));
            
            // 检查数据有效性
            if (keyData.username !== username) return null;
            
            // 检查是否过期（可选，这里设置为30天）
            const maxAge = 30 * 24 * 60 * 60 * 1000; // 30天
            if (Date.now() - keyData.timestamp > maxAge) {
                this.clearPrivateKeyFromLocal(username);
                return null;
            }
            
            return BigInt(keyData.privateKey);
        } catch (error) {
            console.warn('无法从本地存储获取私钥:', error);
            return null;
        }
    }
    
    // 清除本地存储的私钥
    clearPrivateKeyFromLocal(username) {
        try {
            localStorage.removeItem(`zk_key_${username}`);
        } catch (error) {
            console.warn('无法清除本地私钥:', error);
        }
    }
    
    // 生成离散对数零知识证明
    async generateDLogProof() {
        if (!this.x || !this.g || !this.p) {
            throw new Error('Missing required parameters for proof generation');
        }
        
        // 生成随机数 r
        const r = this.randomBigInt(1n, this.p - 1n);
        
        // 计算 t = g^r mod p
        const t = this.modPow(this.g, r, this.p);
        
        // 计算挑战 c = Hash(g || y || t)
        const hashInput = this.g.toString() + this.y.toString() + t.toString();
        const c = await this.hashToBigInt(hashInput, this.p - 1n);
        
        // 计算响应 z = r + c*x mod (p-1)
        const z = (r + c * this.x) % (this.p - 1n);
        
        return { c, z };
    }
    
    // 使用种子派生私钥
    async derivePrivateKey(seed) {
        const encoder = new TextEncoder();
        const data = encoder.encode(seed + this.p.toString() + this.g.toString());
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        
        // 将哈希转换为大整数
        let x = 0n;
        for (let i = 0; i < hashArray.length; i++) {
            x = (x << 8n) + BigInt(hashArray[i]);
        }
        
        // 确保私钥在正确范围内
        return (x % (this.q - 1n)) + 1n;
    }
    
    // 哈希种子
    async hashSeed(seed) {
        const encoder = new TextEncoder();
        const data = encoder.encode(seed);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        return Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    // 将字符串哈希转换为指定范围内的大整数
    async hashToBigInt(input, modulus) {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        
        let result = 0n;
        for (let i = 0; i < hashArray.length; i++) {
            result = (result << 8n) + BigInt(hashArray[i]);
        }
        
        return result % modulus;
    }
    
    // 生成指定范围内的随机BigInt
    randomBigInt(min, max) {
        const range = max - min + 1n;
        const bitLength = range.toString(2).length;
        const byteLength = Math.ceil(bitLength / 8);
        
        while (true) {
            const randomBytes = new Uint8Array(byteLength);
            crypto.getRandomValues(randomBytes);
            
            let randomBigInt = 0n;
            for (let i = 0; i < randomBytes.length; i++) {
                randomBigInt = (randomBigInt << 8n) + BigInt(randomBytes[i]);
            }
            
            randomBigInt = randomBigInt % range;
            const result = min + randomBigInt;
            
            if (result <= max) {
                return result;
            }
        }
    }
    
    // 快速模幂运算
    modPow(base, exponent, modulus) {
        if (modulus === 1n) return 0n;
        
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
    
    // 清理敏感数据
    cleanup() {
        this.x = null;
        this.p = null;
        this.g = null;
        this.y = null;
        this.q = null;
    }
}

// 浏览器环境下的全局暴露
if (typeof window !== 'undefined') {
    window.SecureElGamal = SecureElGamal;
}