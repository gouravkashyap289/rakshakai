FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 rakshak && mkdir /data && chown rakshak:rakshak /data
COPY --chown=rakshak:rakshak app ./app
COPY --chown=rakshak:rakshak demo_emails ./demo_emails
USER rakshak
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--limit-concurrency", "30"]
