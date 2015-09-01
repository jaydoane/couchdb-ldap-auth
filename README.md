ldap-auth
---------

Authentication and Authorization for CouchDB/Cloudant, using the
following modules:

ldap_interface
=========

Uses eldap to connect to LDAP server(s) which are configured to model
users and their associated roles.

ldap_auth
=========

Implements Basic and Cookie based authentication handlers, using
`ldap_interface:authorized_roles(Username, Password)` to obtain the
roles associated with a particular user.

For cookie authentication, POST credentials to the `_ldap_session`
endpoint to obtain an LDAPAuthSession cookie which contains a signed
hash of its contents: name, time issued, and authorized
roles. Subsequent requests using that cookie will automatically be
authorized until the cookie expires, with a default of 10 minutes.
