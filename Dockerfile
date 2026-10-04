FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:/app \
    PORT=8080 \
    NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1/ \
    NEBIUS_MODEL=moonshotai/Kimi-K2.7-Code

WORKDIR /app

# Git and pytest are runtime dependencies of Gauntlet's isolated patch-proof
# workspaces, not development-only tooling for this image.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY victims ./victims
COPY sandbox_checks ./sandbox_checks
COPY tests ./tests
COPY scripts/run_m8_demo.py ./scripts/run_m8_demo.py
COPY scripts/run_p400_live_repair.py ./scripts/run_p400_live_repair.py
COPY evidence ./evidence

RUN python -m pip install --no-cache-dir '.[test]' \
    && groupadd --system gauntlet \
    && useradd --system --gid gauntlet --home-dir /app --shell /usr/sbin/nologin gauntlet \
    && chown -R gauntlet:gauntlet /app

USER gauntlet

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c 'import os, urllib.request; urllib.request.urlopen("http://127.0.0.1:" + os.getenv("PORT", "8080") + "/api/health", timeout=2).read()'

CMD ["sh", "-c", "exec python -m uvicorn scripts.run_m8_demo:app --host 0.0.0.0 --port \"${PORT:-8080}\" --no-access-log"]
