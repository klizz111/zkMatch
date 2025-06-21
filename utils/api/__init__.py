# API模块初始化文件
from .auth_routes import AuthRoutes
from .matching_routes import MatchingRoutes
from .fhe_matching import FHEMatchingRoutes

__all__ = ['AuthRoutes', 'MatchingRoutes', 'FHEMatchingRoutes']