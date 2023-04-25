FROM python:3.10-alpine3.16

ADD . /app

RUN pip install -r /app/requirements.txt
ENV PYTHONPATH=/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
