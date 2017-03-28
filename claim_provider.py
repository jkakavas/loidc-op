from pyop.userinfo import Userinfo
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
from flask import current_app


class LdapUserInfo(Userinfo):
    def __init__(self):
        self._server = Server(current_app.config['LDAP_PROVIDER_URL'])
        self._conn = Connection(self._server, user=current_app.config['LDAP_SERVICEACCOUNT_DN'],
                                password=current_app.config['LDAP_SERVICEACCOUNT_PASSWORD'],
                                authentication='SIMPLE')

    def __contains__(self, user_id):
        search_filter = current_app.config['LDAP_CLAIMS_SEARCH_FILTER'].format(user_id)
        self._conn.bind()
        result = self._conn.search(search_base=current_app.config['LDAP_USER_BASE_DN'], search_filter=search_filter,
                                   search_scope=SUBTREE,
                                   attributes=[])
        self._conn.unbind()
        return result

    def __getitem__(self, user_id):
        return self.get_claims_for(user_id, ['sub'])

    def get_claims_for(self, user_id, requested_claims):
        search_filter = current_app.config['LDAP_CLAIMS_SEARCH_FILTER'].format(user_id)
        self._conn.bind()
        self._conn.search(search_base=current_app.config['LDAP_USER_BASE_DN'], search_filter=search_filter,
                          search_scope=SUBTREE,
                          attributes=self.claims_to_attribute_names(requested_claims))
        response = self._conn.response
        self._conn.unbind()
        current_app.logger.debug('LDAP Search returned {} entries'.format(len(response)))
        # We should only get 1 result
        if len(response) != 1:
            current_app.logger.warn('We should not get more than one result for the same SUB. Failing. ')
            return {}
        return self.attributes_to_claims(response[0]['attributes'])

    @staticmethod
    def claims_to_attribute_names(claims):
        """
        Utility to convert a list with claim names to list of LDAP attribute names
        
        :param claims: 
        :return: 
        """
        _mapping = {'sub': 'uid',
                    'name': 'cn',
                    'given_name': 'givenName',
                    'family_name': 'sn',
                    'email': 'mail'}
        return [_mapping[c] for c in claims if c in _mapping]

    @staticmethod
    def attributes_to_claims(attributes):
        """
        
        :param attributes: 
        :return: 
        """
        _mapping = {'uid': 'sub',
                    'cn': 'name',
                    'givenName': 'given_name',
                    'sn': 'family_name',
                    'mail': 'email'}
        return {_mapping[attr]: attributes[attr] for attr in attributes.keys() if attr in _mapping.keys()}
