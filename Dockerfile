FROM python:3.12-slim-bookworm

# System deps: weasyprint needs pango/cairo; openssh-client for keygen utility
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libcairo2 \
        libffi-dev \
        libssl-dev \
        libjpeg-dev \
        libopenjp2-7-dev \
        zlib1g-dev \
        curl \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Data directory owned by the process
RUN mkdir -p /data/db /data/logs /data/ssh /data/reports

# Honeypot runs on 22, dashboard on 8080
EXPOSE 22 8080

# Default: honeypot. Override with: docker-compose up dashboard
CMD ["python", "-m", "honeypot.main"]
