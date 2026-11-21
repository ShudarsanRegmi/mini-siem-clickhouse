# Multi-stage / lightweight secure container for SIEM Ingestion Gateway
FROM python:3.12-slim

# Create a non-privileged user and group (Least Privilege)
RUN groupadd -r siem && useradd -r -g siem -s /sbin/nologin siem

WORKDIR /app

# Install security updates and dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ /app/src/
COPY config/ /app/config/

# Set ownership to non-root user
RUN chown -R siem:siem /app

USER siem

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV CLICKHOUSE_HOST=clickhouse
ENV CLICKHOUSE_PORT=8123

CMD ["uvicorn", "src.ingestion.collector:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
