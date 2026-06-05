# ============================================================
# Project Cerverus — Docker Sandbox
# Isolated Python 3.11 environment for safe agent execution
# ============================================================
FROM python:3.11-slim

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root sandbox user (security boundary)
RUN useradd --create-home --shell /bin/bash cerverus_user

# Set working directory
WORKDIR /workspace

# Install Python dependencies (as root, before switching user)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files into the container
COPY main.py .
COPY workspace/ ./workspace/
COPY config/ ./config/

# Drop privileges to non-root user
USER cerverus_user

# Default: run the agent orchestration
CMD ["python", "main.py"]
