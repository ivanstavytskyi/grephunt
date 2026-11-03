FROM python:3.6
COPY . /app
RUN pip install -r /app/requirements.txt
USER root
CMD ["python", "/app/app.py"]
