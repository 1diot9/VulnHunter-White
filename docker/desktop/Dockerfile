# VulnHunter-White — Docker edition app image (multi-stage).
# Build context = repository root. Windows Desktop / Linux Engine.

# ---- frontend ----
FROM node:20-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --registry=https://registry.npmmirror.com || npm ci
COPY frontend/ ./
RUN npm run build

# ---- app ----
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULNHUNTER_RUNTIME=docker \
    VULNHUNTER_HOST=0.0.0.0 \
    VULNHUNTER_PORT=16788 \
    PATH="/usr/local/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        openjdk-17-jre-headless \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI only (DooD against the host engine). amd64 / arm64.
ARG TARGETARCH
RUN arch="${TARGETARCH:-amd64}" \
    && case "$arch" in \
         amd64) docker_arch=x86_64 ;; \
         arm64) docker_arch=aarch64 ;; \
         *) echo "unsupported TARGETARCH=$arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${docker_arch}/docker-27.5.1.tgz" \
    | tar -xz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker \
    && docker --version

# jadx (Java decompile). Pin a known release.
ARG JADX_VERSION=1.5.1
RUN curl -fsSL -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /tmp/jadx.zip \
    && jadx --version

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir \
      -i https://pypi.tuna.tsinghua.edu.cn/simple \
      -r /app/backend/requirements.txt \
    || pip install --no-cache-dir -r /app/backend/requirements.txt \
    && pip install --no-cache-dir \
      -i https://pypi.tuna.tsinghua.edu.cn/simple \
      semgrep \
    || pip install --no-cache-dir semgrep

COPY backend/app /app/backend/app
COPY templates /app/templates
COPY docker/sandbox /app/docker/sandbox
COPY docker/integration-sandbox /app/docker/integration-sandbox
COPY docker/desktop/entrypoint.sh /app/docker/desktop/entrypoint.sh
COPY --from=frontend /src/frontend/dist /app/frontend/dist

# Showcase seed (optional; disabled with VULNHUNTER_DEMO_SEED=0).
COPY data/projects/11 /app/data-seed/projects/11

RUN chmod +x /app/docker/desktop/entrypoint.sh \
    && rm -rf /app/data \
    && mkdir -p /data \
    && ln -sfn /data /app/data

WORKDIR /app/backend
EXPOSE 16788
ENTRYPOINT ["/app/docker/desktop/entrypoint.sh"]
