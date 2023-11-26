FROM python:alpine
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python","manage.py","runserver","45.156.26.224:8000"]