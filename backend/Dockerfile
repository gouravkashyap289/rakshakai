FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir -r requirements-postgres.txt && useradd --create-home --uid 10001 rakshak && mkdir /data && chown rakshak:rakshak /data
COPY --chown=rakshak:rakshak app ./app
COPY --chown=rakshak:rakshak demo_emails ./demo_emails
COPY --chown=rakshak:rakshak models ./models
COPY --chown=rakshak:rakshak data ./data
USER rakshak
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --limit-concurrency 30"]
