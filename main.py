from app.app import app, init_database, init_api_routes
import logging

if __name__ == '__main__':
    # 应用启动时初始化
    init_database()
    init_api_routes()
    
    logging.info("Starting Flask application...")
    app.run(debug=True)


