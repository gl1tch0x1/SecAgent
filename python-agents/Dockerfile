FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy python-agents and install
COPY python-agents/ /app/python-agents/
WORKDIR /app/python-agents
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/python-agents

CMD ["python", "-m", "uvicorn", "secagents.infra.health_checks:app", "--host", "0.0.0.0", "--port", "8000"]
