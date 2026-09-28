FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY meridian ./meridian
COPY wsgi.py .
# SQLite by default. Set DATABASE_URL=postgresql://... to use PostgreSQL (see docker-compose.yml).
ENV MERIDIAN_DB=/data/meridian.db
VOLUME /data
EXPOSE 8000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "wsgi:app"]
