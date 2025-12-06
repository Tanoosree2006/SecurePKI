# ---------- Stage 1: builder ----------
FROM python:3.12-slim AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# copy requirements file into image
COPY requirements.txt .

# install dependencies
RUN pip install --no-cache-dir -r requirements.txt


# ---------- Stage 2: runtime ----------
FROM python:3.12-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1 TZ=UTC
WORKDIR /app

# Install cron (+ procps optional so you can run `ps`)
RUN apt-get update && apt-get install -y --no-install-recommends \
      cron tzdata procps \
 && ln -snf /usr/share/zoneinfo/UTC /etc/localtime \
 && echo "UTC" > /etc/timezone \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Bring venv with deps
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# App code
COPY . /app


# Mount points for volumes
RUN mkdir -p /app/data /cron && chmod 755 /app /cron

# Install cron job (must be 0644)
COPY cron/2fa-cron /etc/cron.d/securepki
RUN chmod 0644 /etc/cron.d/securepki

EXPOSE 8080
CMD ["/bin/sh","-c","/usr/sbin/cron && exec /opt/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8080"]
