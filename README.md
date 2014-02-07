SSO service
===========

This single sign-on service offers

- [mod_auth_pubtkt](https://neon1.net/mod_auth_pubtkt/) support
- [SAML2 identity provider](http://en.wikipedia.org/wiki/SAML_2.0) for Google Apps (and others, with additional configuration)
- [OpenID](http://openid.net/) identity provider
- Two-factor authentication with [Google Authenticator](https://code.google.com/p/google-authenticator/) and SMS (bring your own gateway).

For licensing, see [separate file](LICENSE.md).


HTTP headers
------------

Recommended set of HTTP headers:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'
X-Content-Security-Policy: default-src 'none'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'
X-WebKit-CSP: default-src 'none'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'
cache-control: no-cache, no-store, max-age=0, must-revalidate
x-content-type-options: nosniff
x-xss-protection: 1; mode=block
x-frame-options: DENY
strict-transport-security: max-age=86400000; includeSubDomains
```
