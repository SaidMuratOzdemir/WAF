# WAF Dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash waf
RUN chown -R waf:waf /app
USER waf

# Expose ports (will be dynamically managed)
EXPOSE 8081 8082 8083 8084 8085

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import aiohttp; import asyncio; asyncio.run(aiohttp.ClientSession().get('http://localhost:8081/waf/health').close())" || exit 1

# Run the WAF
CMD ["python", "waf.py"]
