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

1. Install packages: for Ubuntu/Debian: ```sudo apt-get install python-pip python-virtualenv swig python-ldap python-dev libssl-dev python-geoip libldap2-dev libsasl2-dev python-m2crypto python-mysqldb redis-server libmysqlclient-dev zlib1g libjpeg-dev```
2. Install requirements: ```pip install -r requirements.txt```
3. Configure your local settings: ```mv sso_frontend/local_settings.py.sample sso_frontend/local_settings.py; vim sso_frontend/local_settings.py```
4. Implement your own SMS gateway: see ```login_frontend/send_sms.py.sample```.
5. Find and replace branding: ```grep -i futurice * -R```
6. Implement your own user sync from user directory (see ```login_frontend/management/commands/refresh_users.py``` and ```login_frontend/utils.py```).
7. Configure uWSGI and nginx. Example configuration files available under ```example_configurations``` folder. Modifying large_client_header_buffers is essential, as valid OpenID/SAML requests easily exceed the default limit.
8. Install npm and node.js. Run ```npm install .``` on node_socket directory. Run app.js. This provides websockets, used for simultaneous sign-ins and sign-outs.

p0f (optional)
------------------

p0f is used for guessing additional information about the client, including OS, network distance, network type and uptime.

```
sudo apt-get install libpcap-dev supervisor
wget http://lcamtuf.coredump.cx/p0f3/releases/p0f-3.06b.tgz
tar -xvzf p0f-3.06b.tgz
cd p0f-3.06b
./build.sh
sudo adduser --system p0f
sudo mkdir /var/local/p0f
```

Create file ```/etc/supervisor/conf.d/p0f.conf``` with contents

```
[program:p0f]
user=root # p0f forks to p0f user
command=/path/to/p0f-3.06b/p0f -i eth0 -f /path/to/p0f-3.06b/p0f.fp -s /var/local/p0f/p0f.sock -o /var/local/p0f/p0f_out.txt -u p0f "port 80 or port 443"
stderr_logfile = /var/log/p0f-err.log
stdout_logfile = /var/log/p0f-stdout.log
```

Set ```P0FSOCKET=/var/local/p0f/p0f.sock``` in local_settings.py.

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

And for ```/static```:

```
cache-control: "public, max-age=86400"
```

See ```example_configurations/nginx/sites-available/default``` for complete configuration file.

Font Content-Type headers
-------------------------

With ```x-content-type-options: nosniff``` content-types are not automatically detected. For nginx, add

```
application/x-font-ttf           ttf;
application/font-woff            woff;
application/x-font-opentype      otf;
application/vnd.ms-fontobject    eot;
```

to ```/etc/nginx/mime.types``` and reload nginx.
