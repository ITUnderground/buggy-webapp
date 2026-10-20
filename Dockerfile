# ============================================================================
#  VulnLab container  —  FOR LOCAL / LAB USE ONLY
#  This image runs a deliberately insecure app. Only publish its port to
#  127.0.0.1 on the host (see docker-compose.yml). Never expose it publicly.
# ============================================================================
FROM python:3.12-slim

WORKDIR /app

# Install deps first so this layer caches when only app code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project (app.py, static/, etc.). Using COPY . . means
# new files are always included; keep .dockerignore current so caches and the
# local sqlite/db files stay out of the image.
COPY . .

# Bind to all interfaces INSIDE the container; host-side exposure is locked
# down to localhost by the port mapping in docker-compose.yml.
ENV HOST=0.0.0.0 \
    PORT=5000 \
    PYTHONUNBUFFERED=1 \
    DB_HOST=db \
    DB_PORT=3306 \
    DB_USER=root \
    DB_PASSWORD=root \
    DB_NAME=appdb

EXPOSE 5000

CMD ["python", "app.py"]
