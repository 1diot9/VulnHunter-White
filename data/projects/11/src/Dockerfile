FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py
COPY board /app/board
COPY templates /app/templates
COPY static /app/static

RUN mkdir -p /app/data /app/static/uploads

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=3s --retries=8 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"

CMD ["python", "app.py"]
