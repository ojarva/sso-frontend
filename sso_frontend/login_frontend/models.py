from django.db import models
import httpagentparser
from distutils.version import LooseVersion

AUTH_LEVEL = (
 ('0', 'Unauthenticated'),
 ('1', 'Access to public content'),
 ('2', 'Basic authentication'),
 ('3', 'Strong authentication')
)

AUTH_STATE = (
 ('0', 'Request basic authentication'),
 ('1', 'Request strong authentication'),
 ('3', 'Authenticated'),
)


class Browser(models.Model):
    bid = models.CharField(max_length=37, primary_key=True) # UUID
    username = models.ForeignKey('User', null=True)
    ua = models.CharField(max_length=250) # browser user agent

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    save_browser = models.BooleanField(default=False)

    auth_level = models.CharField(max_length=1, choices=AUTH_LEVEL, default='0')
    auth_level_valid_until = models.DateTimeField(null=True,blank=True)

    auth_state = models.CharField(max_length=1, choices=AUTH_STATE, default='0')
    auth_state_valid_until = models.DateTimeField(null=True,blank=True)
    
    def compare_ua(self, ua):
        if ua == self.ua:
            return True
        old_ua = httpagentparser.detect(self.ua)
        new_ua = httpagentparser.detect(ua)
        keys = {"os": ["version", "name"], "browser": ["version", "name"]}
        if "os" in old_ua and "os" in new_ua:
            if old_ua["os"] != new_ua["os"]:
                return False
        if "browser" in old_ua and "browser" in new_ua:
            ou = old_ua["browser"]
            nu = new_ua["browser"]
            if ou.get("name") != nu.get("name"):
                return False
            if ou.get("version") == nu.get("version"):
                return True
            try:
                ou_v = LooseVersion(ou.get("version"))
                nu_v = LooseVersion(nu.get("version"))
            except AttributeError:
                return False # Something fishy with version strings
            if nu_v < ou_v:
                return False # downgraded browser version
        return True

class BrowserUsers(models.Model):
    username = models.ForeignKey('User')
    browser = models.ForeignKey('Browser')
    auth_timestamp = models.DateTimeField()
    current_auth_level = models.CharField(max_length=1, choices=AUTH_LEVEL, default='0')
    max_auth_level = models.CharField(max_length=1, choices=AUTH_LEVEL, default='0')

class User(models.Model):
    username = models.CharField(max_length=50, primary_key=True)
    strong_enabled = models.BooleanField(default=False)
    strong_phone = models.CharField(max_length=30, null=True,blank=True)
