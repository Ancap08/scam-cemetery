FROM python:3.12-slim

# The VPS is Ubuntu 24.04. This image brings its own Python 3.12, so the host
# does not need a matching interpreter. The bot only makes outbound connections
# (Telegram long polling). No port is published.

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/checks.db

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin app \
    && mkdir -p /app/data \
    && chown app:app /app/data

COPY pyproject.toml README.md ./
COPY scam_cemetery ./scam_cemetery

RUN pip install --no-cache-dir .

USER app

CMD ["python", "-m", "scam_cemetery"]
