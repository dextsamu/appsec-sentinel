FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["gunicorn", "gestionale.wsgi", "-b", "0.0.0.0:8000"]
