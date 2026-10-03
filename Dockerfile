# hardly — HAR analysis MCP server (stdio)
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/b1tninja/hardly" \
      org.opencontainers.image.description="hardly: HAR analysis MCP server (archive/headless mode)"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HARDLY_RUNTIME_DIR=/workspace/.hardly-cache \
    HARDLY_WORKSPACE=/workspace

WORKDIR /app

# Non-root user
RUN useradd --create-home --uid 1000 hardly \
    && mkdir -p /workspace \
    && chown -R hardly:hardly /workspace /app

COPY pyproject.toml README.md ./
COPY docs ./docs
COPY skills ./skills
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

USER hardly

# Default: MCP over stdio (Cursor / Docker MCP Toolkit)
ENTRYPOINT ["python", "-m", "hardly"]
