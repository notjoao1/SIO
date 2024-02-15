# Segurança Informática e nas Organizações, 2023-2024

## Assignment 2 - Application Security Verification Standard (ASVS)

### Introduction

This project aims to audit a previously created web application (DETI Memorabilia Store from 1st project) according to the requirements for level 1 of the *Application Security Verification Standard* ([ASVS](https://owasp.org/www-project-application-security-verification-standard/)).

The project structure is the following:

- `app_org/` - original web application. Same as `app_sec/` from the 1st project. This is the web application that will be audited based on the ASVS level 1 requirements.
- `app_sec/` - secure web application. Implements fixes for 10 selected key issues identified during the audit and 2 features (password strength evaluation + multi-factor authentication)
- `analysis/` - contains audit [checklist](https://github.com/shenril/owasp-asvs-checklist) and other information describing the identified issues and their implemented fixes.

### Authors

- João Dourado 108636
- Miguel Belchior 108287
- Diogo Silva 107647
- Rafael Vilaça 107476
- Miguel Cruzeiro 107660
