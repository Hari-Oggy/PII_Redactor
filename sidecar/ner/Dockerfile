# ==============================================================================
# Stage 1: Build
# ==============================================================================
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the spacy model
RUN python -m spacy download en_core_web_lg

# Copy proto files and generate stubs
COPY ner.proto .
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ner.proto

# ==============================================================================
# Stage 2: Runtime
# ==============================================================================
FROM python:3.13-slim

WORKDIR /app

# Create a non-root user
RUN groupadd -r piiuser && useradd -r -g piiuser piiuser

# Copy virtual environment and generated proto files from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/*_pb2*.py /app/

# Enable venv and optimize python
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy remaining application code
COPY server.py run_demo.py ./

# Change ownership
RUN chown -R piiuser:piiuser /app

USER piiuser

EXPOSE 50051

CMD ["python", "server.py"]
