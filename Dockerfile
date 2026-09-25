FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MSF_SERVER=127.0.0.1 \
    MSF_PORT=55553 \
    MSF_SSL=false \
    MCP_REQUIRE_AUTH=auto

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY MetasploitMCP.py .
COPY .env.example .

RUN useradd --create-home --uid 10001 mcp \
    && mkdir -p /app/payloads \
    && chown -R mcp:mcp /app

USER mcp

EXPOSE 8085

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:8085/healthz', timeout=3).read()"

CMD ["python", "MetasploitMCP.py", "--transport", "http", "--host", "0.0.0.0", "--port", "8085"]
