# Multi-arch base image (supports linux/amd64 and linux/arm64)
FROM python:3.12-slim

WORKDIR /app

# Install curl and iproute2 for network leak tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy runner script
COPY runner.py .

CMD ["python", "runner.py"]
