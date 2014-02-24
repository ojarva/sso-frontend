import os.path

# Django settings for sso_frontend project.

URL_PREFIX = ""

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS
LOGIN_URL = URL_PREFIX+"/internal_login"

HUEY = {
    'backend': 'huey.backends.redis_backend',  # required.
    'name': 'sso_frontend',
    'connection': {'host': 'localhost', 'port': 6379},
    'always_eager': False, # Defaults to False when running via manage.py run_huey

    # Options to pass into the consumer when running ``manage.py run_huey``
    'consumer_options': {'workers': 4},
}

# DATABASES are configured in local_settings. Use mysql/postgresql instead of sqlite3
#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
#        'NAME': 'sso',
#        'USER': '',
#        'PASSWORD': '',
#        'HOST': '',                      # Empty for localhost through domain sockets or '127.0.0.1' for localhost through TCP.
#        'PORT': '',                      # Set to empty string for default.
#    }
#}


CACHES = {
    'default': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': 'localhost:6379',
        'OPTIONS': {
            'DB': 1,
            'PASSWORD': '',
            'PARSER_CLASS': 'redis.connection.HiredisParser'
        },
    },
    'ratelimit': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': 'localhost:6379',
        'OPTIONS': {
            'DB': 2,
            'PASSWORD': '',
            'PARSER_CLASS': 'redis.connection.HiredisParser'
        },
    },	
}

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), '../')
GEOIP_DB = PROJECT_ROOT+"data/GeoLite2-City.mmdb"


LOGIN_REDIRECT_URL = URL_PREFIX+'/idp/sso/post/response/preview/'

# SAML2IDP metadata settings
SAML2IDP_CONFIG = {
    'autosubmit': False,
    'issuer': 'https://login.futurice.com',
    'signing': True,
    'certificate_file': PROJECT_ROOT + '/saml2idp/keys/certificate.pem',
    'private_key_file': PROJECT_ROOT + '/saml2idp/keys/private-key.pem'
}
SAML2IDP_REMOTES = {
    # Group of SP CONFIGs.
    # friendlyname: SP config
    'google_apps': {
        'acs_url': 'https://www.google.com/a/futurice.com/acs',
        'processor': 'saml2idp.google_apps.Processor',
    }
}

RATELIMIT_ENABLE=True
RATELIMIT_USE_CACHE="ratelimit"


DATETIME_FORMAT='Y-m-d H:i:s'
DATE_FORMAT='Y-m-d'
TIME_FORMAT='H:i'
SHORT_DATE_FORMAT='Y-m-d'
SHORT_DATETIME_FORMAT='Y-m-d H:i'

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
ALLOWED_HOSTS = []

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Helsinki'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = False

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = ''

SESSION_COOKIE_AGE=24*60*60*7
SESSION_SERIALIZER="django.contrib.sessions.serializers.PickleSerializer"
SESSION_ENGINE='redis_sessions.session'
SESSION_REDIS_PREFIX="dsess"

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = os.path.join(os.path.dirname(__file__), '../static')

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
    'compressor.finders.CompressorFinder',
)



# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'login_frontend.middleware.InLoggingMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # Uncomment the next line for simple clickjacking protection:
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'login_frontend.middleware.OutLoggingMiddleware', # logging middleware should be before browsermiddleware, as browsermiddleware might abort on process_request.
    'login_frontend.middleware.BrowserMiddleware',
    'login_frontend.middleware.ViewLoggingMiddleware',
)

DISABLE_TIMING_LOGGING=False

from django.contrib import messages
MESSAGE_TAGS = {
    messages.ERROR: 'danger'
}

TEMPLATE_CONTEXT_PROCESSORS = (
"django.contrib.auth.context_processors.auth",
"django.core.context_processors.debug",
"django.core.context_processors.i18n",
"django.core.context_processors.media",
"django.core.context_processors.static",
"django.core.context_processors.tz",
"django.contrib.messages.context_processors.messages",
"login_frontend.context_processors.add_browser",
"login_frontend.context_processors.add_user",
"login_frontend.context_processors.session_info",
"login_frontend.context_processors.add_static_timestamp"
)


CSRF_COOKIE_SECURE=True
CSRF_COOKIE_HTTPONLY=True
CSRF_FAILURE_VIEW="login_frontend.error_views.error_csrf"

handler400 = "login_frontend.error_views.error_400"
handler403 = "login_frontend.error_views.error_403"
handler404 = "login_frontend.error_views.error_404"
handler500 = "login_frontend.error_views.error_500"


ROOT_URLCONF = 'sso_frontend.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'sso_frontend.wsgi.application'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

COMPRESS_ENABLED = True
#COMPRESS_OFFLINE = True

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'compressor',
    'login_frontend',
    'openid_provider',
    'south',
    'huey.djhuey',
    'saml2idp',
    'django.contrib.admin',
    'admin_frontend',
    'cspreporting',
)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format' : "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
            'datefmt' : "%Y-%m-%d %H:%M:%S"
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'logfile_main': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/main",
            'maxBytes': 50000000,
            'backupCount': 10,
            'formatter': 'standard',
        },

        'logfile_saml': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/saml",
            'maxBytes': 50000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

        'logfile_openid': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/openid",
            'maxBytes': 50000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

        'logfile_users': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/users",
            'maxBytes': 50000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

        'logfile_django': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/django",
            'maxBytes': 50000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

        'logfile_errors': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/errors",
            'maxBytes': 50000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

        'logfile_timing': {
            'level':'DEBUG',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/timing",
            'maxBytes': 500000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

        'logfile_request_timing': {
            'level':'INFO',
            'class':'logging.handlers.RotatingFileHandler',
            'filename': PROJECT_ROOT + "/logs/request_timing",
            'maxBytes': 500000000,
            'backupCount': 100,
            'formatter': 'standard',
        },

    },
    'loggers': {
        'django': {
          'handlers': ['logfile_django'],
          'propagate': False,
        },
        'django.request': {
            'handlers': ['mail_admins', 'logfile_errors'],
            'level': 'ERROR',
            'propagate': True,
        },
        'request_timing': {
          'handlers': ['logfile_request_timing'],
          'propagate': False,
          'level': 'INFO',
        },
        'users': {
          'handlers': ['logfile_users'],
          'propagate': True,
          'level': 'DEBUG',
        },
        'openid_provider': {
          'handlers': ['logfile_openid'],
          'propagate': True,
          'level': 'DEBUG',
        },
        'saml2idp': {
          'handlers': ['logfile_saml'],
          'propagate': True,
          'level': 'DEBUG',
        },
        'timing_data': {
          'handlers': ['logfile_timing'],
          'propagate': False,
          'level': 'DEBUG',
        },
        '': {
          'handlers': ['logfile_main'],
          'propagate': True,
          'level': 'DEBUG',
        },
    }
}




from M2Crypto import DSA
IP_NETWORKS = [
]

FQDN = None

LDAP_SERVER = None # for example, "ldaps://ldap.example.com"
LDAP_USER_BASE_DN = None # for example, "uid=%s,ou=People,dc=example,dc=com"
LDAP_GROUPS_BASE_DN = None # for example, "ou=Groups,dc=example,dc=com"
LDAP_IGNORE_SSL=False # skip LDAP SSL certificate checks
TOKEN_MAP = {} # map of LDAP groups to pubtkt tokens. For example, {"Administrators": "admins", "ExternalContractors": "ext"}

PUBTKT_PRIVKEY=None
PUBTKT_PUBKEY=None
PUBTKT_ALLOWED_DOMAINS=[]
SAML_PUBKEY=None

SECURE_COOKIES = True

FUM_API_ENDPOINT=None
FUM_ACCESS_TOKEN=None

OPENID_PROVIDER_AX_EXTENSION=True
OPENID_FAILED_DISCOVERY_AS_VALID=True
OPENID_TRUSTED_ROOTS=[]


from local_settings import *
try:
   pass
except ImportError:
    pass

check_keys = ["FQDN", "PUBTKT_PRIVKEY", "PUBTKT_PUBKEY", "SAML_PUBKEY", "LDAP_SERVER", "LDAP_USER_BASE_DN", "LDAP_GROUPS_BASE_DN"]
for key_name in check_keys:
    if key_name not in locals():
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured("%s is not defined." % key_name)
