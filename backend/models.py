"""
VulnKB 数据模型定义
- User:          管理员用户（环境变量初始化，不开放注册）
- Category:      攻击模式目录/分类（如 "反序列化"、"SQL注入"）
- AttackPattern: 攻击模式条目，必须归属于某个 Category
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(128), nullable=False)


class Category(Base):
    """
    攻击模式目录，用于组织归类攻击模式条目。
    例如 "反序列化"、"SQL注入"、"XSS" 等。
    """
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(String(512), nullable=False, default="")
    created_at = Column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # 一对多关系：一个目录包含多个攻击模式
    patterns = relationship(
        "AttackPattern", back_populates="category", cascade="all, delete-orphan"
    )


class AttackPattern(Base):
    """
    攻击模式知识条目，必须归属于一个 Category。
    - title:       条目标题
    - tags:        逗号分隔的标签字符串
    - content:     Markdown 格式正文
    - category_id: 所属目录外键
    """
    __tablename__ = "attack_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    category_id = Column(
        Integer, ForeignKey("categories.id", ondelete="CASCADE"), nullable=False
    )
    title = Column(String(256), nullable=False)
    tags = Column(String(512), nullable=False, default="")
    content = Column(Text, nullable=False, default="")
    created_at = Column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    category = relationship("Category", back_populates="patterns")


class UserSession(Base):
    """
    用户活跃会话记录，用于实现多地同时登录上限控制。
    每次登录创建一条记录，登出或被挤下线时删除。
    """
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, default="")
    created_at = Column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
