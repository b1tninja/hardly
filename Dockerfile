# hardly — HAR analysis MCP server (stdio)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HARDLY_CACHE_DIR=/workspace/.hardly-cache \
    HARDLY_WORKSPACE=/workspace

WORKDIR /app

# Non-root user
RUN useradd --create-home --uid 1000 hardly \
    && mkdir -p /workspace \
    && chown -R hardly:hardly /workspace /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

USER hardly

# Default: MCP over stdio (Cursor / Docker MCP Toolkit)
ENTRYPOINT ["python", "-m", "hardly"]
