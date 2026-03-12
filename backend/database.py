"""
VulnKB 数据库连接与初始化模块
- SQLite 单文件数据库，路径为 <项目>/data/vulnkb.db
- 启动时自动建表、注入管理员账号
"""

import os
import logging

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from passlib.hash import bcrypt

from models import Base, User

logger = logging.getLogger("vulnkb")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE_PATH = os.path.join(DATA_DIR, "vulnkb.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)


# SQLite 默认不强制外键约束，需要手动开启
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    """FastAPI 依赖注入：获取数据库会话，请求结束后自动关闭"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    数据库初始化：
    1. 创建所有表（已存在则跳过）
    2. 初始化管理员账号
    """
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_password = os.getenv("ADMIN_PASSWORD")

        if not admin_password:
            logger.warning("ADMIN_PASSWORD 未设置，使用默认密码（仅限开发环境）")
            admin_password = "admin123"

        existing = db.query(User).filter_by(username=admin_username).first()
        if existing is None:
            hashed = bcrypt.hash(admin_password)
            db.add(User(username=admin_username, hashed_password=hashed))
            db.commit()
            logger.info("管理员账号 [%s] 已创建", admin_username)
        else:
            logger.info("管理员账号 [%s] 已存在，跳过初始化", admin_username)
    finally:
        db.close()
