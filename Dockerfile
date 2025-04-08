FROM python:3.10.12-slim
# RUN useradd -ms /bin/sh -u 1001 developer
# USER developer

# Set workdir
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install "psycopg[binary,pool]"
RUN pip install psycopg2-binary

# Copy app code
COPY . .

# Run FastAPI with Gunicorn and Uvicorn worker
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "--bind", "0.0.0.0:8000"]