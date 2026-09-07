FROM python:3.12-slim

WORKDIR /app

# 系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# 依赖用 lock 精确固定 (pip-compile 生成),再 --no-deps 安装本包。
# 分两步既让依赖层可缓存,也避免构建时解析器重新选版本 —— 镜像内容与
# CI 扫出的 SBOM 才能对得上。
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY pyproject.toml ./
COPY app/ ./app/
RUN pip install --no-cache-dir --no-deps -e .

# Alembic 迁移 (config 目录,非 Python 包) — editable install 之后 COPY,
# 避免 setuptools flat-layout 把 alembic 误判为顶层包
COPY alembic.ini ./
COPY alembic/ ./alembic/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
