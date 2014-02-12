SSO service
===========

This single sign-on service offers

- [mod_auth_pubtkt](https://neon1.net/mod_auth_pubtkt/) support
- [SAML2 identity provider](http://en.wikipedia.org/wiki/SAML_2.0) for Google Apps (and others, with additional configuration)
- [OpenID](http://openid.net/) identity provider
- Two-factor authentication with [Google Authenticator](https://code.google.com/p/google-authenticator/) and SMS (bring your own gateway).

For licensing, see [separate file](LICENSE.md).

Installation
------------

1. Install requirements: ```pip install -r requirements.txt```
2. Configure your local settings: ```mv sso_frontend/local_settings.py.sample sso_frontend/local_settings.py; vim sso_frontend/local_settings.py```


Cookies
-------

- ```Browser.C_BID = "v2browserid"``` - unique, strictly private browser ID
- ```Browser.C_BID_PUBLIC = "v2public-browserid"``` - public browser ID - sharing this is not an issue. Should be used in logging / on error messages / when asking for browser identity.
- ```Browser.C_BID_SESSION = "v2sessionbid"``` - unique per-session browser ID. This cookie is used to reliably (?) detect browser restarts.
- ```auth_pubtkt``` - session based [pubtkt](https://neon1.net/mod_auth_pubtkt/install.html) cookie
- ```csrftoken``` - [Django CSRF token](https://docs.djangoproject.com/en/dev/ref/contrib/csrf/)

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

Font Content-Type headers
-------------------------

With ```x-content-type-options: nosniff``` content-types are not automatically detected. For apache2, add

```
AddType application/x-font-ttf           .ttf
AddType application/font-woff            .woff
AddType application/x-font-opentype      .otf
AddType application/vnd.ms-fontobject    .eot
```

to configuration file and reload apache.
