FROM python:3.13-slim

# Create a non-root system user and group (Hardening)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code 
COPY . .

# Secure file permissions and switch to non-root user (Hardening)
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 7010

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7010"]
