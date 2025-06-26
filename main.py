#!/usr/bin/env python3
"""
项目启动文件
运行此文件启动Flask应用程序
"""

import sys
import os
import logging

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.app import app, init_database, init_api_routes

def main():
    """主启动函数"""
    
    try:
        # 初始化数据库
        init_database()
        
        # 初始化API路由
        init_api_routes()
        
        app.run(
            host='0.0.0.0',  # 允许外部访问
            port=5000,       # 端口号
            debug=False       # 开发模式
        )
        
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        logging.error(f"启动失败: {e}")
        print(f"启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()