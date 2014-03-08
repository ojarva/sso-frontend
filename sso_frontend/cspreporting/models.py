from django.db import models
from login_frontend.models import User

# Create your models here.
class CSPReport(models.Model):
    username = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    bid_public = models.CharField(max_length=37, null=True, blank=True) # UUID

    reported_at = models.DateTimeField(auto_now_add=True, db_index=True)

    csp_raw = models.TextField()
    document_uri = models.CharField(max_length=2000, blank=True, null=True)
    referrer = models.CharField(max_length=2000, blank=True, null=True)
    violated_directive = models.CharField(max_length=2000, blank=True, null=True)
    blocked_uri = models.CharField(max_length=2000, blank=True, null=True)
    source_file = models.CharField(max_length=2000, blank=True, null=True, db_index=True)
    line_number = models.IntegerField(null=True, blank=True)
    column_number = models.IntegerField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)


    class Meta:
        ordering = ["-reported_at"]

    def __unicode__(self):
        return u"%s - %s - %s - %s" % (self.username, self.bid_public, self.reported_at, self.source_file)
