"""
VulnKB 身份验证模块
- JWT Token 签发与校验（含 jti 用于会话追踪）
- 密码哈希比对（bcrypt，常量时间，防时序攻击）
- IP 登录失败锁定（5 次错误锁 1 小时）
- 多地同时登录上限（最多 5 个会话）
"""

import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from database import get_db
from models import User, UserSession

SECRET_KEY: str = os.getenv("SECRET_KEY", "insecure-dev-key-change-me")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
COOKIE_NAME = "vulnkb_token"

MAX_SESSIONS = 5
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 60

# ---------- IP 登录失败追踪（内存级，重启清零） ----------

_ip_lock = threading.Lock()
_ip_attempts: dict[str, dict] = {}
# 格式: { "1.2.3.4": {"count": 3, "first_fail": datetime, "locked_until": datetime|None} }


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_ip_locked(ip: str) -> Optional[datetime]:
    """返回锁定到期时间，未锁定返回 None"""
    with _ip_lock:
        rec = _ip_attempts.get(ip)
        if not rec:
            return None
        locked_until = rec.get("locked_until")
        if locked_until and datetime.now(timezone.utc) < locked_until:
            return locked_until
        if locked_until and datetime.now(timezone.utc) >= locked_until:
            del _ip_attempts[ip]
        return None


def record_failed_attempt(ip: str) -> Optional[datetime]:
    """记录一次失败尝试，如果触发锁定则返回锁定到期时间"""
    now = datetime.now(timezone.utc)
    with _ip_lock:
        rec = _ip_attempts.get(ip)
        if not rec:
            _ip_attempts[ip] = {"count": 1, "first_fail": now, "locked_until": None}
            return None

        # 如果距离第一次失败已超过 1 小时，重新计数
        if now - rec["first_fail"] > timedelta(hours=1):
            _ip_attempts[ip] = {"count": 1, "first_fail": now, "locked_until": None}
            return None

        rec["count"] += 1
        if rec["count"] >= MAX_LOGIN_ATTEMPTS:
            rec["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
            return rec["locked_until"]
        return None


def clear_failed_attempts(ip: str) -> None:
    with _ip_lock:
        _ip_attempts.pop(ip, None)


def get_remaining_attempts(ip: str) -> int:
    with _ip_lock:
        rec = _ip_attempts.get(ip)
        if not rec:
            return MAX_LOGIN_ATTEMPTS
        return max(0, MAX_LOGIN_ATTEMPTS - rec["count"])


# ---------- 密码 ----------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.verify(plain_password, hashed_password)


# ---------- JWT ----------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> tuple[str, str]:
    """
    签发 JWT，返回 (token, jti)。
    jti 用于关联数据库中的会话记录。
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    )
    jti = uuid.uuid4().hex
    to_encode.update({"exp": expire, "jti": jti})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti


# ---------- 会话管理 ----------

def create_session(db: Session, user_id: int, jti: str, ip: str) -> None:
    """创建登录会话，如果已达上限则踢掉最旧的"""
    sessions = (
        db.query(UserSession)
        .filter_by(user_id=user_id)
        .order_by(UserSession.created_at.asc())
        .all()
    )
    while len(sessions) >= MAX_SESSIONS:
        db.delete(sessions.pop(0))

    db.add(UserSession(user_id=user_id, jti=jti, ip_address=ip))
    db.commit()


def remove_session_by_jti(db: Session, jti: str) -> None:
    session = db.query(UserSession).filter_by(jti=jti).first()
    if session:
        db.delete(session)
        db.commit()


# ---------- 当前用户依赖 ----------

def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    """
    从 Cookie 解析 JWT，校验 jti 对应的会话是否仍然有效。
    会话被踢出（超过 5 个登录点）后该 token 将被拒绝。
    """
    token: Optional[str] = request.cookies.get(COOKIE_NAME)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登录",
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        jti: Optional[str] = payload.get("jti")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证凭据",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="认证令牌已过期或无效",
        )

    user = db.query(User).filter_by(username=username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在",
        )

    # 如果 JWT 包含 jti，验证对应会话是否仍存在（被挤下线时会话已删除）
    if jti:
        session_exists = db.query(UserSession).filter_by(jti=jti).first()
        if not session_exists:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="该会话已失效（可能被新登录挤下线）",
            )

    return user
