FROM python:3.10

#mkcert
RUN apt-get update && apt-get install -y \
    libnss3-tools

RUN wget -O mkcert https://github.com/FiloSottile/mkcert/releases/download/v1.4.3/mkcert-v1.4.3-linux-amd64 && \
    chmod +x mkcert && \
    mv mkcert /usr/local/bin/

RUN mkcert -install

RUN mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1

#django
COPY . .
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN pip install -r requirements.txt
RUN python3 manage.py migrate
RUN python3 manage.py collectstatic --noinput
EXPOSE 8000
CMD ["python3", "manage.py", "runserver_plus", "--cert-file" ,"cert.pem","--key-file","key.pem","0.0.0.0:8000"]
