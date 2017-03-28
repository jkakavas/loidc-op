# Federation Aware OP 
Federation aware OP implementation using [pyOP](https://github.com/SUNET/pyop) and [fedoidc](https://github.com/OpenIDC/fedoidc)
Uses LDAP as a backend for authentication and user info
## Install dependencies
```bash
pip install -r requirements.txt # install the dependencies
```
## Configure depending to your environment
```bazaar
SERVER_NAME = 'localhost:9090'
# change this to a random string
SECRET_KEY = 'secret_key'
SESSION_COOKIE_NAME='pyop_session'
SESSION_TYPE = 'filesystem'
SUBJECT_ID_HASH_SALT = 'salt'
PREFERRED_URL_SCHEME = 'https'

#LDAP backend related
LDAP_USERNAME_SEARCH_FILTER = '(uid={})'
LDAP_CLAIMS_SEARCH_FILTER = '(uid={})'
LDAP_USER_BASE_DN = 'ou=users,dc=example,dc=com'
LDAP_PROVIDER_URL = 'ldap://127.0.0.1:10389'
LDAP_ANONYMOUS_SEARCH = True
LDAP_SERVICEACCOUNT_DN = ''
LDAP_SERVICEACCOUNT_PASSWORD = ''
```

## Run the OP
```bash
pip install -r requirements.txt # install the dependencies
gunicorn wsgi:app -b 127.0.0.1:9090 --certfile fedop.crt --keyfile fedop.key
```