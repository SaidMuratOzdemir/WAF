# ./waf/Dockerfile

FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# <<< FIX: Copy requirements from the correct path and install
COPY ./waf/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# <<< FIX: Copy only the necessary files into the container
COPY ./waf/ /app/
COPY ./api/app/models.py /app/

# Create non-root user
RUN useradd --create-home --shell /bin/bash waf
RUN chown -R waf:waf /app
USER waf

# Expose ports (dynamically managed by the app)
EXPOSE 8081 8082 8083 8084 8085

# Health check can remain if you have a default port like 8081 running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import aiohttp; import asyncio; async def check(): async with aiohttp.ClientSession() as session: async with session.get('http://localhost:8081/waf/health') as response: assert response.status == 200; asyncio.run(check())" || exit 1

# Run the WAF
CMD ["python", "waf.py"]