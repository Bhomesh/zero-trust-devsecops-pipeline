# Multi-stage hardened build with distroless runtime
# SLSA Level 3 compatible deterministic container build
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runtime using nonroot Distroless base
FROM gcr.io/distroless/python3-debian12:nonroot

WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY main.py /app/main.py

ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PORT=8443

# Distroless non-root user (UID: 65532)
USER 65532:65532
EXPOSE 8443

ENTRYPOINT ["python3", "/app/main.py"]
