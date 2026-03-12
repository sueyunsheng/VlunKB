FROM python:3.11-slim

LABEL maintainer="VulnKB" \
      description="VulnKB - 私有攻击模式知识库"

# 安全：以非 root 用户运行
RUN groupadd -r vulnkb && useradd -r -g vulnkb -m vulnkb

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# data 目录由 docker-compose volume 挂载，此处仅确保目录存在
RUN mkdir -p /app/data && chown -R vulnkb:vulnkb /app

USER vulnkb

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
