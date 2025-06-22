// 安全的ElGamal实现 
class SecureElGamal {
    constructor(bits = 512) {  
        this.bits = 512;  
        this.p = null;
        this.g = null;
        this.y = null;
        this.x = null;
        this.q = null;
        this.currentSessionId = null;  // 当前session ID
    }
    
    // 客户端生成密码
    generateSeed() {
        const array = new Uint8Array(32);  // 32字节
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array)).replace(/[+/=]/g, '').substring(0, 32);
    }
    
    // 生成用户友好的种子（包含分隔符便于阅读）
    generateReadableSeed() {
        const seed = this.generateSeed();
        // 每8个字符添加一个分隔符
        return seed.match(/.{1,8}/g).join('-');
    }
    
    // 用户注册 - 第一步：从服务端获取root的群参数
    async register(username, seed) {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || '注册失败');
        }
        
        const data = await response.json();
        // 使用root用户的群参数
        this.p = BigInt(data.p);
        this.g = BigInt(data.g);
        this.q = BigInt(data.q);
        
        // 客户端本地生成512位私钥
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
        
        // 注册成功后立即保存私钥到本地存储
        this.savePrivateKeyToLocal(username, this.x);
        
        return {
            success: true,
            message: data.message,
            public_key: {
                p: this.p.toString(),
                g: this.g.toString(),
                y: this.y.toString()
            }
        };
    }
    

    // 验证session
    async validateSession() {
        try {
            // 从localStorage获取session
            const sessionData = localStorage.getItem('zk_current_session');
            if (!sessionData || sessionData === 'null' || sessionData === 'undefined') {
                return false;
            }

            let session;
            try {
                session = JSON.parse(sessionData);
            } catch (parseError) {
                console.warn('Session数据损坏，清除localStorage');
                localStorage.removeItem('zk_current_session');
                return false;
            }

            if (!session.username || !session.token) {
                return false;
            }

            // 向服务器验证session
            const response = await fetch('/api/validate_session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: session.username,
                    token: session.token
                })
            });

            const result = await response.json();
            
            if (result.valid) {
                this.currentSession = session;
                return true;
            } else {
                // session无效，清除localStorage
                localStorage.removeItem('zk_current_session');
                this.currentSession = null;
                return false;
            }
        } catch (error) {
            console.error('Session验证失败:', error);
            localStorage.removeItem('zk_current_session');
            this.currentSession = null;
            return false;
        }
    }
    
    // 零知识证明登录
    async zkLogin(username, seed) {
        // console.log('calling zkLogin with username:', username, 'and seed:', seed);
        try {
            // 第一步：获取登录挑战
            const challengeResponse = await fetch('/api/login_challenge', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username
                })
            });
            
            if (!challengeResponse.ok) {
                const error = await challengeResponse.json();
                throw new Error(error.error || '获取登录挑战失败');
            }
            
            const challengeData = await challengeResponse.json();
            // console.log('Challenge Data:', challengeData);
            // setTimeout(() => {}, 100000000000);
            
            // 设置公钥参数
            this.p = BigInt(challengeData.p);
            this.g = BigInt(challengeData.g);
            this.y = BigInt(challengeData.y);
            this.q = (this.p - 1n) / 2n;
            
            // 使用种子派生私钥
            this.x = await this.derivePrivateKey(seed);
            // 保存到本地存储
            this.savePrivateKeyToLocal(username, this.x);
            
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
            // console.log('Verify Data:', verifyData); 
            
            // 保存session ID到本地存储和实例中
            if (verifyData.sessionId) {
                this.currentSessionId = verifyData.sessionId;
                this.saveSessionToLocal(username, verifyData.sessionId);
            }
            
            return {
                success: true,
                message: verifyData.message,
                sessionId: verifyData.sessionId,
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
            
            // 检查是否过期（这里设置为30天）
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
    
    // 保存session ID到本地存储
    saveSessionToLocal(username, sessionId) {
        // console.log('Saving session to local storage:', username, sessionId);
        try {
            const sessionData = {
                username: username,
                sessionId: sessionId,
                timestamp: Date.now()
            };
            
            const currentSessionData = {
                username: username,
                token: sessionId  
            };
            
            localStorage.setItem(`zk_session_${username}`, JSON.stringify(sessionData));
            localStorage.setItem('zk_current_session', JSON.stringify(currentSessionData));  
            localStorage.setItem('zk_current_user', username);
        } catch (error) {
            console.warn('无法保存session到本地存储:', error);
        }
    }
    
    // 从本地存储获取session ID
    getSessionFromLocal(username) {
        try {
            const sessionDataStr = localStorage.getItem(`zk_session_${username}`);
            if (!sessionDataStr) return null;
            
            const sessionData = JSON.parse(sessionDataStr);
            if (sessionData.username !== username) return null;
            
            return sessionData.sessionId;
        } catch (error) {
            console.warn('无法从本地存储获取session:', error);
            return null;
        }
    }
    
    // 获取当前用户和session
    getCurrentSession() {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            const username = localStorage.getItem('zk_current_user');
            return { sessionId, username };
        } catch (error) {
            return { sessionId: null, username: null };
        }
    }
    
    // 验证session是否有效
    async validateSession(sessionId = null) {
        try {
            const useSessionId = sessionId || this.currentSessionId || localStorage.getItem('zk_current_session');
            if (!useSessionId) return false;
            
            const response = await fetch('/api/validate_session', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${useSessionId}`
                }
            });
            
            if (!response.ok) return false;
            
            const data = await response.json();
            return data.valid;
        } catch (error) {
            console.warn('验证session失败:', error);
            return false;
        }
    }
    
    // 获取用户信息（需要有效session）
    async getUserInfo() {
        try {
            const sessionId = this.currentSessionId || localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session，请先登录');
            }
            
            const response = await fetch('/api/user_info', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${sessionId}`
                }
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '获取用户信息失败');
            }
            
            return await response.json();
        } catch (error) {
            throw new Error(`获取用户信息失败: ${error.message}`);
        }
    }
    
    // 更新用户资料（需要有效session）
    async updateProfile(profileData) {
        try {
            const sessionId = this.currentSessionId || localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session，请先登录');
            }
            
            const response = await fetch('/api/update_profile', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`
                },
                body: JSON.stringify(profileData)
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '更新资料失败');
            }
            
            return await response.json();
        } catch (error) {
            throw new Error(`更新资料失败: ${error.message}`);
        }
    }
    
    // 用户登出
    async logout() {
        try {
            const sessionId = this.currentSessionId || localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }
            
            const response = await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`
                },
                body: JSON.stringify({})
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '登出失败');
            }
            
            // 清除本地存储的session信息
            this.clearSessionFromLocal();
            
            return await response.json();
        } catch (error) {
            // 即使服务器端登出失败，也清除本地session
            this.clearSessionFromLocal();
            throw new Error(`登出失败: ${error.message}`);
        }
    }
    
    // 清除本地存储的私钥和session信息
    clearPrivateKeyFromLocal(username) {
        try {
            localStorage.removeItem(`zk_key_${username}`);
            localStorage.removeItem(`zk_session_${username}`);
            if (localStorage.getItem('zk_current_user') === username) {
                localStorage.removeItem('zk_current_session');
                localStorage.removeItem('zk_current_user');
            }
        } catch (error) {
            console.warn('无法清除本地私钥和session:', error);
        }
    }
    
    // 清除本地存储的session信息
    clearSessionFromLocal() {
        try {
            const username = localStorage.getItem('zk_current_user');
            if (username) {
                localStorage.removeItem(`zk_session_${username}`);
            }
            localStorage.removeItem('zk_current_session');
            localStorage.removeItem('zk_current_user');
            this.currentSessionId = null;
        } catch (error) {
            console.warn('清除本地session失败:', error);
        }
    }
    
    // 生成dlogProof
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
    
    // 使用种子派生512位私钥
    async derivePrivateKey(seed) {
        const encoder = new TextEncoder();
        const data = encoder.encode(seed + this.p.toString() + this.g.toString() + this.q.toString());
        
        let hashBuffer = await crypto.subtle.digest('SHA-512', data);  
        
        const hashArray = new Uint8Array(hashBuffer);
        
        // 将哈希转换为大整数
        let x = 0n;
        for (let i = 0; i < hashArray.length; i++) {
            x = (x << 8n) + BigInt(hashArray[i]);
        }
        
        // 确保私钥在正确范围内 [1, q-1]
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