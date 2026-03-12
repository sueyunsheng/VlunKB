# VulnKB - 私有攻击模式知识库

基于 FastAPI + SQLite + Jinja2 + TailwindCSS 构建的私有攻击模式知识库，支持 Markdown 编辑、目录分类管理、数据导入导出。

## 功能特性

- **强制登录**：无注册入口，管理员账号由环境变量初始化
- **目录分类**：攻击模式按目录组织（如反序列化、SQL注入），支持 CRUD
- **Markdown 编辑器**：分栏实时预览，工具栏快捷插入，代码高亮
- **左侧导航栏**：可折叠的目录树，快速跳转任意文章
- **数据导入/导出**：一键 JSON 导出备份，支持文件导入迁移
- **安全机制**：
  - JWT + HttpOnly Cookie 鉴权
  - 同一用户最多 5 个并发会话，超出自动踢掉最旧会话
  - 同一 IP 连续输错密码 5 次，锁定该 IP 登录 1 小时
- **HTTPS 部署**：Nginx 反向代理 + 自签 SSL 证书，VulnKB 不直接暴露公网

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Python 3.11、FastAPI、Uvicorn |
| 数据库 | SQLite + SQLAlchemy ORM |
| 前端 | Jinja2 模板、TailwindCSS (CDN)、marked.js、highlight.js |
| 反向代理 | Nginx (alpine) + 自签 SSL |
| 部署 | Docker + docker-compose |

## 项目结构

```
attack_web/
├── backend/
│   ├── main.py              # FastAPI 主入口、路由
│   ├── auth.py              # JWT 签发/校验、IP 锁定、会话管理
│   ├── models.py            # SQLAlchemy 数据模型
│   ├── database.py          # 数据库连接与初始化
│   ├── requirements.txt     # Python 依赖
│   ├── data/                # SQLite 数据库文件（自动生成）
│   └── templates/           # Jinja2 HTML 模板
├── nginx/
│   ├── nginx.conf           # Nginx 反向代理配置
│   └── ssl/
│       ├── gen-cert.sh      # 自签证书生成脚本
│       ├── server.crt       # SSL 证书（生成后出现）
│       └── server.key       # SSL 私钥（生成后出现）
├── data/                    # Docker 挂载的持久化数据目录
├── Dockerfile
├── docker-compose.yml
├── .env.example             # 环境变量模板
└── README.md
```

## 部署架构

```
浏览器 --HTTPS:6868--> [ Nginx 容器 ] --HTTP:8000--> [ VulnKB 容器 ]
                         (对外暴露)                   (仅 Docker 内部网络)
```

- Nginx 对外暴露 HTTPS 端口，处理 SSL 终止
- VulnKB 不暴露任何端口到宿主机，仅 Nginx 可通过 Docker 内部网络访问
- Nginx 转发 `X-Real-IP` / `X-Forwarded-For` 头，IP 锁定功能可正确识别客户端

---

## 云服务器 HTTPS 部署（推荐）

**前置要求**：云服务器已安装 [Docker](https://docs.docker.com/get-docker/) 和 [Docker Compose](https://docs.docker.com/compose/install/)，安全组/防火墙已放行 `6868` 端口。

### 第一步：上传项目到服务器

```bash
# 本地打包上传（或用 git clone）
scp -r attack_web/ root@你的服务器IP:/opt/
ssh root@你的服务器IP
cd /opt/attack_web
```

### 第二步：生成自签 SSL 证书

```bash
cd nginx/ssl
bash gen-cert.sh
cd ../..
```

执行后会在 `nginx/ssl/` 下生成 `server.crt` 和 `server.key`。

### 第三步：配置环境变量

```bash
cp .env.example .env
vi .env
```

**务必修改以下配置**：

```ini
# 设置强密码
ADMIN_PASSWORD=你的强密码

# 生成并填入 JWT 密钥（在服务器上执行以下命令获取）
# python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=生成的64位十六进制字符串

# HTTPS 对外端口（默认 6868）
HTTPS_PORT=6868
```

### 第四步：构建并启动

```bash
docker-compose up -d --build
```

### 第五步：验证服务

```bash
# 查看容器状态（应看到 vulnkb 和 vulnkb-nginx 均为 Up）
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 第六步：浏览器访问

```
https://你的公网IP:6868
```

首次访问浏览器会提示"证书不受信任"（因为是自签证书），点击"高级" -> "继续访问"即可。使用 `.env` 中配置的账号密码登录。

### 常用运维命令

```bash
# 查看实时日志
docker-compose logs -f

# 仅查看 VulnKB 日志
docker-compose logs -f vulnkb

# 停止所有服务
docker-compose down

# 代码更新后重新构建
docker-compose up -d --build

# 查看容器状态
docker-compose ps

# 进入 VulnKB 容器排查问题
docker exec -it vulnkb sh
```

### 更换端口

修改 `.env` 中的 `HTTPS_PORT`，同时修改云服务器安全组/防火墙规则：

```ini
HTTPS_PORT=9443
```

然后重启：

```bash
docker-compose down && docker-compose up -d
```

---

## 本地开发运行

**前置要求**：Python 3.11+。

```bash
# 1. 克隆项目
git clone <仓库地址>
cd attack_web

# 2. 创建虚拟环境
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# 3. 安装依赖
pip install -r backend/requirements.txt

# 4. 创建环境配置
cp .env.example .env
# 编辑 .env 填入实际值

# 5. 启动服务
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000

# 开发模式（热重载）
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload

# 6. 浏览器打开 http://127.0.0.1:8000
```

## 环境变量说明

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| `ADMIN_USERNAME` | 否 | `admin` | 管理员用户名 |
| `ADMIN_PASSWORD` | **是** | `admin123` (仅开发) | 管理员密码，生产环境务必修改 |
| `SECRET_KEY` | **是** | - | JWT 签名密钥，建议 64 位随机十六进制字符串 |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 否 | `480` | JWT 令牌过期时间（分钟） |
| `APP_PORT` | 否 | `8000` | VulnKB 内部服务端口 |
| `HTTPS_PORT` | 否 | `6868` | Nginx 对外暴露的 HTTPS 端口 |

## 数据备份与迁移

1. **导出**：登录后点击顶部导航栏的数据管理图标，或访问 `/data-manage`，点击"下载导出文件"
2. **导入**：在同一页面上传之前导出的 JSON 文件，同名目录自动合并

也可以直接备份 `data/vulnkb.db` 文件（SQLite 单文件数据库）。

## 安全注意事项

- 生产部署时**务必修改** `ADMIN_PASSWORD` 和 `SECRET_KEY`
- VulnKB 容器不直接暴露端口到公网，所有外部流量经 Nginx HTTPS 加密后转发
- 云服务器安全组/防火墙仅需放行 `HTTPS_PORT`（默认 6868），其余端口保持关闭
- 同一 IP 连续 5 次密码错误将被锁定 1 小时
- 同一用户最多 5 个并发登录会话
- 自签证书仅用于加密传输，浏览器会提示不受信任；如需去掉告警可购买域名并使用 Let's Encrypt
