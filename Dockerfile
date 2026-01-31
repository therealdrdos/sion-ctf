FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (git is needed for aider)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster, more reliable dependency resolution
RUN pip install --no-cache-dir uv

COPY pyproject.toml .

# Use uv to install dependencies (handles complex dependency resolution better)
RUN uv pip install --system --no-cache .

COPY app/ app/

RUN mkdir -p data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
