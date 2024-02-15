# Original Version - secure app from 1st project

## Running Instructions

- How to create user with manager permissions via command line
```bash
# How to create manager in command line
cd app_org/;
# assumin venv is already created
source venv/bin/activate;
# creating manager
echo "from accounts.models import *; u = User(email='manager@example.com', full_name='manager_name'); u.set_password('Segur@7654321'); u.is_manager=True; u.save();" | python3 manage.py shell
```

- With Virtual Environment

```bash
# create venv
python3 -m venv venv
# use venv
source venv/bin/activate
# install requirements
pip install -r requirements.txt
# migrate the database
python3 manage.py migrate
# serve static files
python3 manage.py collectstatic
# runserver
python3 manage.py runserver
```

- With Docker

```bash
# 2 Dockerfiles in app/ and app_sec/ folders
# build docker image
sudo docker build -t app .
# run docker image
sudo docker run --name app_c -dp 8000:8000 app
```
