FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -m netsentinel.train --skip-zero-day
EXPOSE 8000
# Dashboard runs unprivileged; for live sniffing run the CLI with --net=host --cap-add=NET_RAW
RUN useradd -m app && chown -R app /app
USER app
CMD ["uvicorn", "netsentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
