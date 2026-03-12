"""
VulnKB - FastAPI 主入口
路由总览：
  - 登录 / 登出
  - 目录（Category）CRUD
  - 攻击模式（AttackPattern）CRUD（隶属于目录）
  - 全局鉴权中间件
"""

import json
import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from auth import (
    ALGORITHM,
    COOKIE_NAME,
    SECRET_KEY as AUTH_SECRET_KEY,
    check_ip_locked,
    clear_failed_attempts,
    create_access_token,
    create_session,
    get_client_ip,
    get_current_user,
    get_remaining_attempts,
    record_failed_attempt,
    remove_session_by_jti,
    verify_password,
)
from database import get_db, init_db
from models import AttackPattern, Category, User, UserSession

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("vulnkb")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("VulnKB 启动完成")
    yield
    logger.info("VulnKB 正在关闭")


app = FastAPI(title="VulnKB", docs_url=None, redoc_url=None, lifespan=lifespan)

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "templates")
)

PUBLIC_PATHS = {"/login", "/favicon.ico"}


class AuthMiddleware(BaseHTTPMiddleware):
    """拦截所有未认证请求，重定向至登录页"""

    async def dispatch(self, request: Request, call_next):
        if request.url.path not in PUBLIC_PATHS:
            token = request.cookies.get(COOKIE_NAME)
            if not token:
                return RedirectResponse(url="/login", status_code=302)
        return await call_next(request)


app.add_middleware(AuthMiddleware)


# ========================================================================
#  登录 / 登出
# ========================================================================


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    ip = get_client_ip(request)
    locked_until = check_ip_locked(ip)
    ctx: dict = {"request": request, "error": "", "locked_until": None}
    if locked_until:
        remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
        ctx["error"] = f"当前 IP 因多次输入错误已被锁定，请 {remaining} 分钟后再试"
        ctx["locked_until"] = locked_until.isoformat()
    return templates.TemplateResponse("login.html", ctx)


@app.post("/login", response_class=HTMLResponse)
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """验证账密 → 检查 IP 锁定 → 签发 JWT → 创建会话 → 写入 Cookie"""
    ip = get_client_ip(request)

    # 检查 IP 是否被锁定
    locked_until = check_ip_locked(ip)
    if locked_until:
        remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": f"当前 IP 因多次输入错误已被锁定，请 {remaining} 分钟后再试",
                "locked_until": locked_until.isoformat(),
            },
            status_code=403,
        )

    user: User | None = db.query(User).filter_by(username=username).first()
    if user is None or not verify_password(password, user.hashed_password):
        lock_time = record_failed_attempt(ip)
        remaining_attempts = get_remaining_attempts(ip)
        if lock_time:
            error_msg = "密码错误次数过多，当前 IP 已被锁定 1 小时"
        else:
            error_msg = f"用户名或密码错误（还剩 {remaining_attempts} 次尝试机会）"
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": error_msg,
                "locked_until": lock_time.isoformat() if lock_time else None,
            },
            status_code=400,
        )

    # 登录成功：清除失败记录，签发 token，创建会话
    clear_failed_attempts(ip)
    token, jti = create_access_token(data={"sub": user.username})
    create_session(db, user.id, jti, ip)

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 8,
    )
    return response


@app.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    # 删除当前会话记录
    token = request.cookies.get(COOKIE_NAME)
    if token:
        try:
            from jose import jwt as _jwt
            payload = _jwt.decode(token, AUTH_SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            jti = payload.get("jti")
            if jti:
                remove_session_by_jti(db, jti)
        except Exception:
            pass

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key=COOKIE_NAME)
    return response


# ========================================================================
#  首页 - 目录总览
# ========================================================================


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    q: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    首页：展示所有目录卡片。
    支持按目录名搜索（q），并统计每个目录下的条目数。
    """
    query = db.query(Category)
    if q:
        query = query.filter(Category.name.contains(q))
    categories = query.order_by(Category.updated_at.desc()).all()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "categories": categories,
            "q": q,
            "user": current_user,
        },
    )


# ========================================================================
#  目录 CRUD
# ========================================================================


@app.get("/category/new", response_class=HTMLResponse)
async def category_new_page(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """渲染新建目录表单"""
    return templates.TemplateResponse(
        "category_form.html",
        {"request": request, "category": None, "user": current_user},
    )


@app.post("/category/new")
async def category_create(
    name: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """创建新目录"""
    existing = db.query(Category).filter_by(name=name.strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="同名目录已存在")

    now = datetime.now(timezone.utc)
    cat = Category(
        name=name.strip(),
        description=description.strip(),
        created_at=now,
        updated_at=now,
    )
    db.add(cat)
    db.commit()
    db.refresh(cat)
    return RedirectResponse(url=f"/category/{cat.id}", status_code=302)


@app.get("/category/{cat_id}", response_class=HTMLResponse)
async def category_detail(
    request: Request,
    cat_id: int,
    q: str = "",
    tag: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """展示目录下的所有攻击模式条目，支持搜索和标签筛选"""
    category = db.get(Category, cat_id)
    if not category:
        raise HTTPException(status_code=404, detail="目录不存在")

    query = db.query(AttackPattern).filter_by(category_id=cat_id)
    if q:
        query = query.filter(AttackPattern.title.contains(q))
    if tag:
        query = query.filter(AttackPattern.tags.contains(tag))

    patterns = query.order_by(AttackPattern.updated_at.desc()).all()

    # 收集本目录下所有标签
    all_patterns = db.query(AttackPattern).filter_by(category_id=cat_id).all()
    all_tags: set[str] = set()
    for p in all_patterns:
        if p.tags:
            for t in p.tags.split(","):
                stripped = t.strip()
                if stripped:
                    all_tags.add(stripped)

    return templates.TemplateResponse(
        "category_detail.html",
        {
            "request": request,
            "category": category,
            "patterns": patterns,
            "all_tags": sorted(all_tags),
            "q": q,
            "tag": tag,
            "user": current_user,
        },
    )


@app.get("/category/{cat_id}/edit", response_class=HTMLResponse)
async def category_edit_page(
    request: Request,
    cat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """渲染编辑目录表单"""
    category = db.get(Category, cat_id)
    if not category:
        raise HTTPException(status_code=404, detail="目录不存在")
    return templates.TemplateResponse(
        "category_form.html",
        {"request": request, "category": category, "user": current_user},
    )


@app.post("/category/{cat_id}/edit")
async def category_update(
    cat_id: int,
    name: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """更新目录信息"""
    category = db.get(Category, cat_id)
    if not category:
        raise HTTPException(status_code=404, detail="目录不存在")

    dup = db.query(Category).filter(
        Category.name == name.strip(), Category.id != cat_id
    ).first()
    if dup:
        raise HTTPException(status_code=400, detail="同名目录已存在")

    category.name = name.strip()
    category.description = description.strip()
    category.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse(url=f"/category/{cat_id}", status_code=302)


@app.post("/category/{cat_id}/delete")
async def category_delete(
    cat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """删除目录及其下所有攻击模式（级联删除）"""
    category = db.get(Category, cat_id)
    if not category:
        raise HTTPException(status_code=404, detail="目录不存在")
    db.delete(category)
    db.commit()
    return RedirectResponse(url="/", status_code=302)


# ========================================================================
#  攻击模式 - 创建（路由在 /pattern/{id} 之前注册）
# ========================================================================


@app.get("/category/{cat_id}/pattern/new", response_class=HTMLResponse)
async def pattern_new_page(
    request: Request,
    cat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """渲染新建攻击模式编辑器"""
    category = db.get(Category, cat_id)
    if not category:
        raise HTTPException(status_code=404, detail="目录不存在")

    categories = db.query(Category).order_by(Category.name).all()
    return templates.TemplateResponse(
        "edit.html",
        {
            "request": request,
            "pattern": None,
            "category": category,
            "categories": categories,
            "user": current_user,
        },
    )


@app.post("/category/{cat_id}/pattern/new")
async def pattern_create(
    cat_id: int,
    title: str = Form(...),
    tags: str = Form(""),
    content: str = Form(""),
    category_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """创建攻击模式条目，归入指定目录"""
    target_cat = db.get(Category, category_id)
    if not target_cat:
        raise HTTPException(status_code=400, detail="目标目录不存在")

    now = datetime.now(timezone.utc)
    pattern = AttackPattern(
        category_id=category_id,
        title=title.strip(),
        tags=tags.strip(),
        content=content,
        created_at=now,
        updated_at=now,
    )
    db.add(pattern)
    db.commit()
    db.refresh(pattern)
    return RedirectResponse(url=f"/pattern/{pattern.id}", status_code=302)


# ========================================================================
#  攻击模式 - 详情 / 编辑 / 删除
# ========================================================================


@app.get("/pattern/{pattern_id}", response_class=HTMLResponse)
async def pattern_detail(
    request: Request,
    pattern_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """查看攻击模式详情"""
    pattern = db.get(AttackPattern, pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail="条目不存在")
    return templates.TemplateResponse(
        "detail.html",
        {"request": request, "pattern": pattern, "user": current_user},
    )


@app.get("/pattern/{pattern_id}/edit", response_class=HTMLResponse)
async def pattern_edit_page(
    request: Request,
    pattern_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """渲染编辑攻击模式编辑器"""
    pattern = db.get(AttackPattern, pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail="条目不存在")

    categories = db.query(Category).order_by(Category.name).all()
    return templates.TemplateResponse(
        "edit.html",
        {
            "request": request,
            "pattern": pattern,
            "category": pattern.category,
            "categories": categories,
            "user": current_user,
        },
    )


@app.post("/pattern/{pattern_id}/edit")
async def pattern_update(
    pattern_id: int,
    title: str = Form(...),
    tags: str = Form(""),
    content: str = Form(""),
    category_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """更新攻击模式条目"""
    pattern = db.get(AttackPattern, pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail="条目不存在")

    target_cat = db.get(Category, category_id)
    if not target_cat:
        raise HTTPException(status_code=400, detail="目标目录不存在")

    pattern.title = title.strip()
    pattern.tags = tags.strip()
    pattern.content = content
    pattern.category_id = category_id
    pattern.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse(url=f"/pattern/{pattern.id}", status_code=302)


@app.post("/pattern/{pattern_id}/delete")
async def pattern_delete(
    pattern_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """删除攻击模式条目"""
    pattern = db.get(AttackPattern, pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail="条目不存在")
    cat_id = pattern.category_id
    db.delete(pattern)
    db.commit()
    return RedirectResponse(url=f"/category/{cat_id}", status_code=302)


# ========================================================================
#  API - 侧边栏目录树 / 数据导出 / 数据导入
# ========================================================================


@app.get("/api/sidebar")
async def api_sidebar(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """返回目录树结构 JSON，供前端侧边栏渲染"""
    categories = db.query(Category).order_by(Category.name).all()
    return [
        {
            "id": cat.id,
            "name": cat.name,
            "patterns": [
                {"id": p.id, "title": p.title}
                for p in sorted(cat.patterns, key=lambda x: x.updated_at, reverse=True)
            ],
        }
        for cat in categories
    ]


@app.get("/api/export")
async def api_export(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """一键导出所有目录和攻击模式为 JSON 文件"""
    categories = db.query(Category).order_by(Category.name).all()
    data = {
        "version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "categories": [
            {
                "name": cat.name,
                "description": cat.description,
                "patterns": [
                    {
                        "title": p.title,
                        "tags": p.tags,
                        "content": p.content,
                        "created_at": p.created_at.isoformat() if p.created_at else None,
                        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
                    }
                    for p in cat.patterns
                ],
            }
            for cat in categories
        ],
    }
    json_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    filename = f"vulnkb_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return StreamingResponse(
        iter([json_bytes]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/data-manage", response_class=HTMLResponse)
async def data_manage_page(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """数据管理页面（导入 / 导出）"""
    return templates.TemplateResponse(
        "data_manage.html",
        {"request": request, "user": current_user},
    )


@app.post("/api/import")
async def api_import(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    从 JSON 文件导入数据。
    导入策略：同名目录合并（追加条目），不同名目录新建。
    """
    try:
        content = await file.read()
        data = json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="无效的 JSON 文件")

    if "categories" not in data:
        raise HTTPException(status_code=400, detail="JSON 格式不正确，缺少 categories 字段")

    imported_cats = 0
    imported_patterns = 0
    now = datetime.now(timezone.utc)

    for cat_data in data["categories"]:
        cat_name = cat_data.get("name", "").strip()
        if not cat_name:
            continue

        # 同名目录合并，否则新建
        category = db.query(Category).filter_by(name=cat_name).first()
        if category is None:
            category = Category(
                name=cat_name,
                description=cat_data.get("description", ""),
                created_at=now,
                updated_at=now,
            )
            db.add(category)
            db.flush()
            imported_cats += 1

        for p_data in cat_data.get("patterns", []):
            title = p_data.get("title", "").strip()
            if not title:
                continue
            pattern = AttackPattern(
                category_id=category.id,
                title=title,
                tags=p_data.get("tags", ""),
                content=p_data.get("content", ""),
                created_at=now,
                updated_at=now,
            )
            db.add(pattern)
            imported_patterns += 1

    db.commit()
    return JSONResponse({
        "success": True,
        "message": f"导入完成：新建 {imported_cats} 个目录，{imported_patterns} 篇文章",
    })
