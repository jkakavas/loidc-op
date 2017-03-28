from ldap3 import Connection, Server, SUBTREE
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPExceptionError
from flask import current_app


class LDAPAuthenticator:
    def __init__(self):
        self._server = Server(current_app.config['LDAP_PROVIDER_URL'])

    def authenticate(self, credentials):
        auth_result = False
        if current_app.config['LDAP_ANONYMOUS_SEARCH']:
            conn = Connection(self._server)
        else:
            conn = Connection(self._server, user=current_app.config['LDAP_SERVICEACCOUNT_DN'],
                              password=current_app.config['LDAP_SERVICEACCOUNT_PASSWORD'],
                              authentication='SIMPLE')
        try:
            conn.bind()
            search_filter = current_app.config['LDAP_USERNAME_SEARCH_FILTER'].format(credentials['username'])
            if conn.search(search_base=current_app.config['LDAP_USER_BASE_DN'], search_filter=search_filter,
                           search_scope=SUBTREE,
                           attributes=[]):
                user_information = conn.response[0]
                user_dn = user_information['dn']
                conn = Connection(self._server,
                                  authentication='SIMPLE',
                                  user=user_dn,
                                  password=credentials['password'],
                                  raise_exceptions=True)
                try:
                    auth_result = conn.bind()
                    current_app.logger.debug('Authentication for {} successful'.format(user_dn))
                except LDAPInvalidCredentialsResult as e:
                    current_app.logger.debug('Authentication for {} failed'.format(user_dn))
                    current_app.logger.warn('error authenticating: {}'.format(e.message))
        except LDAPInvalidCredentialsResult as e:
            current_app.logger.error('Error connecting to the server. Authentication for service account failed')
            current_app.logger.error(e)
        except LDAPExceptionError as e:
            current_app.logger.error('error connecting to the server')
            current_app.logger.error(e)
        finally:
            conn.unbind()
        return auth_result
