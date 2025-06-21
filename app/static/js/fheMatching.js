// FHE匹配系统的JavaScript实现
class FHEMatching {
    constructor() {
        this.systemParams = null;
        this.userPrivateKey = null;
        this.userPublicKey = null;
        this.contactInfo = null;
    }

    // 初始化系统参数
    async initializeSystem() {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            const response = await fetch('/api/system_params', {
                headers: {
                    'Authorization': `Bearer ${sessionId}`
                }
            });

            if (!response.ok) {
                throw new Error('获取系统参数失败');
            }

            const data = await response.json();
            if (data.success) {
                this.systemParams = data.params;
                console.log('系统参数初始化成功');
                return true;
            }
            return false;
        } catch (error) {
            console.error('初始化系统参数失败:', error);
            return false;
        }
    }

    // 生成DH密钥对
    generateDHKeypair() {
        if (!this.systemParams) {
            throw new Error('系统参数未初始化');
        }

        const { p, g, q } = this.systemParams;
        this.userPrivateKey = this.randomInt(1, q - 1);
        this.userPublicKey = this.modPow(g, this.userPrivateKey, p);
        
        console.log('DH密钥对生成成功');
        return { privateKey: this.userPrivateKey, publicKey: this.userPublicKey };
    }

    // 计算共享密钥
    computeSharedSecret(otherPublicKey) {
        if (!this.userPrivateKey || !this.systemParams) {
            throw new Error('私钥或系统参数未初始化');
        }

        const { p } = this.systemParams;
        const sharedSecret = this.modPow(otherPublicKey, this.userPrivateKey, p);
        console.log('共享密钥计算成功');
        return sharedSecret;
    }

    // 准备加密的联系方式
    prepareContactInfo(contactInfo, sharedSecret) {
        if (!this.systemParams) {
            throw new Error('系统参数未初始化');
        }

        this.contactInfo = contactInfo;
        const { p, g } = this.systemParams;
        
        // 将联系方式转换为数字
        const contactHash = this.hashToNumber(contactInfo);
        const contactValue = contactHash % (p - 1) + 1;
        
        // 使用共享密钥加密
        const r = this.randomInt(1, p - 1);
        const c1 = this.modPow(g, r, p);
        const c2 = (contactValue * this.modPow(sharedSecret, r, p)) % p;
        
        console.log('联系方式加密完成');
        return { c1, c2 };
    }

    // 加密用户选择
    encryptChoice(choice, targetPublicKey) {
        if (!this.systemParams) {
            throw new Error('系统参数未初始化');
        }

        const { p, g } = this.systemParams;
        let plaintext;
        
        if (choice) {
            // 接受：加密明文1
            plaintext = 1;
        } else {
            // 拒绝：加密随机数
            plaintext = this.randomInt(2, p - 1);
        }

        // ElGamal加密
        const r = this.randomInt(1, p - 1);
        const c1 = this.modPow(g, r, p);
        const c2 = (plaintext * this.modPow(targetPublicKey, r, p)) % p;

        console.log(`选择加密完成: ${choice ? '接受' : '拒绝'}`);
        return { c1, c2 };
    }

    // 提交选择到服务器
    async submitChoice(targetUser, encryptedContact, encryptedChoice) {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            const response = await fetch('/api/submit_choice', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`
                },
                body: JSON.stringify({
                    target_user: targetUser,
                    encrypted_contact: encryptedContact,
                    encrypted_choice: encryptedChoice
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

    // 获取匹配状态
    async getMatchingStatus(targetUser) {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            const response = await fetch(`/api/matching_status?target_user=${targetUser}`, {
                headers: {
                    'Authorization': `Bearer ${sessionId}`
                }
            });

            if (!response.ok) {
                throw new Error('获取匹配状态失败');
            }

            return await response.json();
        } catch (error) {
            console.error('获取匹配状态失败:', error);
            throw error;
        }
    }

    // 解密匹配结果
    decryptResult(encryptedResult) {
        if (!this.userPrivateKey || !this.systemParams) {
            throw new Error('私钥或系统参数未初始化');
        }

        try {
            const { p } = this.systemParams;
            const { c1, c2 } = encryptedResult;
            
            const s = this.modPow(c1, this.userPrivateKey, p);
            const sInv = this.modPow(s, p - 2, p); // 模逆
            const plaintext = (c2 * sInv) % p;
            
            console.log('结果解密完成:', plaintext);
            return plaintext;
        } catch (error) {
            console.error('解密结果失败:', error);
            return 0;
        }
    }

    // 解密联系方式
    decryptContactInfo(encryptedContact, sharedSecret) {
        if (!this.systemParams) {
            throw new Error('系统参数未初始化');
        }

        try {
            const { p } = this.systemParams;
            const { c1, c2 } = encryptedContact;
            
            // 简化的解密过程
            const s = this.modPow(sharedSecret, c1, p);
            const sInv = this.modPow(s, p - 2, p);
            const contactValue = (c2 * sInv) % p;
            
            // 这里是简化版本，实际应用中需要更复杂的恢复机制
            console.log('联系方式解密完成');
            return `contact_${contactValue}`;
        } catch (error) {
            console.error('解密联系方式失败:', error);
            return '无法解密';
        }
    }

    // 获取每日推送
    async getDailyPushes() {
        try {
            const sessionId = localStorage.getItem('zk_current_session');
            if (!sessionId) {
                throw new Error('未找到有效的session');
            }

            const response = await fetch('/api/daily_pushes', {
                headers: {
                    'Authorization': `Bearer ${sessionId}`
                }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || '获取推送失败');
            }

            const data = await response.json();
            console.log('获取到推送:', data.pushes.length, '个');
            return data.pushes;
        } catch (error) {
            console.error('获取推送失败:', error);
            throw error;
        }
    }

    // 工具函数：模幂运算
    modPow(base, exp, mod) {
        if (typeof base === 'bigint' || typeof exp === 'bigint' || typeof mod === 'bigint') {
            return Number(BigInt(base) ** BigInt(exp) % BigInt(mod));
        }
        
        let result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 === 1) {
                result = (result * base) % mod;
            }
            exp = Math.floor(exp / 2);
            base = (base * base) % mod;
        }
        return result;
    }

    // 工具函数：生成随机整数
    randomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    // 工具函数：字符串哈希为数字
    hashToNumber(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // 转换为32位整数
        }
        return Math.abs(hash);
    }
}

// 浏览器环境下的全局暴露
if (typeof window !== 'undefined') {
    window.FHEMatching = FHEMatching;
}