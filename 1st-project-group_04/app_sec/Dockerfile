FROM python:3.10
COPY . .
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN pip install -r requirements.txt
RUN python3 manage.py migrate
RUN python3 manage.py collectstatic --noinput
EXPOSE 8000
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
