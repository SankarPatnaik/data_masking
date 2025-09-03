
# Note: Installing spaCy models inside slim images can be heavy.
# For regex-only mode or if models are pre-baked, adjust as needed.
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System deps for cryptography; add build tools if you need spaCy builds.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional: download spaCy small model (comment out if not needed)
# RUN python -m spacy download en_core_web_sm

COPY . .

ENV MASKING_CONFIG_PATH=masking_config.yaml

EXPOSE 8000
CMD ["uvicorn", "src.service.app:app", "--host", "0.0.0.0", "--port", "8000"]
