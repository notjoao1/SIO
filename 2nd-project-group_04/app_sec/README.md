# Secured Version

## Running Instructions

- How to create user with manager permissions via command line
```bash
# How to create manager in command line
cd app_sec/;
# assumin venv is already created
source venv/bin/activate;
# creating manager
echo "from accounts.models import *; u = User(email='manager@example.com', full_name='manager_name'); u.set_password('Segur@7654321'); u.is_manager=True; u.save();" | python3 manage.py shell
```

- Run without TLS

```bash
# create venv
python3 -m venv venv
# use venv
source venv/bin/activate
# install requirements
pip install -r requirements.txt
# make migrations
python3 manage.py makemigrations
# migrate the database
python3 manage.py migrate
# serve static files
python3 manage.py collectstatic
# runserver
python3 manage.py runserver
```

- Run with TLS

```bash
# create venv
python3 -m venv venv
# use venv
source venv/bin/activate
# install libnss3-tools
sudo apt install libnss3-tools
# download mkcert
wget -O mkcert https://github.com/FiloSottile/mkcert/releases/download/v1.4.3/mkcert-v1.4.3-linux-amd64 && chmod +x mkcert && sudo mv mkcert /usr/local/bin/
# install local CA
mkcert -install
# create certificate for localhost
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1
# install requirements
pip install -r requirements.txt
# make migrations
python3 manage.py makemigrations
# migrate the database
python3 manage.py migrate
# serve static files
python3 manage.py collectstatic
# runserver
python3 manage.py runserver_plus --cert-file cert.pem --key-file key.pem
```

- With Docker

```bash
# 2 Dockerfiles in app/ and app_sec/ folders
# build docker image
sudo docker build -t app .
# run docker image
sudo docker run --name app_c -dp 8000:8000 app
```
