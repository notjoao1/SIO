# Segurança Informática e nas Organizações, 2023-2024

## Assignment 1 - Exposed Vulnerabilities in the University of Aveiro's DETI Memorabilia Online Shop

### Introduction

This report aims to explain vulnerabilities discovered in an online shop specializing in selling DETI memorabilia at the University of Aveiro.

The project contains 2 versions of a web application:

- `app`: contains implemented vulnerabilites
- `app_sec`: secure version of `app`

Our web app has the following features:

- Authentication (register, log in)
- Buy DETI merchandise products
  - add/remove to shopping cart
  - add/remove to favourites
  - review products (textual, star rating and attached files)
- Filter shop products
- Search for products by name
- Edit Profile (name and e-mail)
- View previous orders (download related in-voice file)
- Manager Dashboard
  - add/remove products
  - add categories
  - view all orders

### Authors

- João Dourado 108636
- Miguel Belchior 108287
- Diogo Silva 107647
- Rafael Vilaça 107476
- Miguel Cruzeiro 107660

### Initial Remarks

The website we examined for vulnerabilities was not built from scratch. We used a template e-commerce website available on GitHub [here](https://github.com/zareisajad/online-shop-django). This website uses the Django Framework which allows interaction with a SQLite3 database through object oriented code. The templates served by Django are build using HTML and bootstrap.
Further development has occured to customize the website to meet our specific requirements.

### Running Instructions

- With Virtual Environment

```bash
# clone repository
git clone git@github.com:detiuaveiro/1st-project-group_04.git
# go to app (cd app/) or app_sec (cd app_sec/)
cd app/
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

## Vulnerabilities Implemented

| Vulnerability | CWE(s)                                                                                                       | Documentation                             |
| ------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| 1             | **CWE-23**: Relative Path Traversal, **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor | [CWE-23-200.md](analysis/CWE-23-200.md)   |
| 2             | **CWE-521**: Weak Password Requirements                                                                      | [CWE-521.md](analysis/CWE-521.md)         |
| 3             | **CWE-89**: SQL Injection                                                                                    | [CWE-89.md](analysis/CWE-89.md)           |
| 4             | **CWE-79**: Cross-Site Scripting (XSS), **CWE-352**: Cross-Site Request Forgery (CSRF)                       | [CWE-79-352.md](analysis/CWE-79-352.md)   |
| 5             | **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor, **CWE-285**: Improper Authorization | [CWE-200-285.md](analysis/CWE-200-285.md) |
| 6             | **CWE-434**: Unrestricted File Upload                                                                        | [CWE-434.md](analysis/CWE-434.md)         |
| 7             | **CWE-798** - Use of Hard-coded Credentials                                                                  | [CWE-798.md](analysis/CWE-798.md)         |
| 8             | **CWE-307**: Improper Restriction of Excessive Authentication Attempts                                       | [CWE-307.md](analysis/CWE-307.md)         |



## References:

- [CVSS Scoring System](https://nvd.nist.gov/vuln-metrics/cvss)
- [CWE-23](https://cwe.mitre.org/data/definitions/23.html)
- [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-521](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-285](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-307](https://cwe.mitre.org/data/definitions/307.html)

