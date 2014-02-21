# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):

        # Changing field 'CSPReport.username'
        db.alter_column(u'cspreporting_cspreport', 'username', self.gf('django.db.models.fields.CharField')(max_length=100, null=True))

        # Changing field 'CSPReport.bid_public'
        db.alter_column(u'cspreporting_cspreport', 'bid_public', self.gf('django.db.models.fields.CharField')(max_length=37, null=True))

    def backwards(self, orm):

        # Changing field 'CSPReport.username'
        db.alter_column(u'cspreporting_cspreport', 'username', self.gf('django.db.models.fields.CharField')(default=' ', max_length=100))

        # Changing field 'CSPReport.bid_public'
        db.alter_column(u'cspreporting_cspreport', 'bid_public', self.gf('django.db.models.fields.CharField')(default=' ', max_length=37))

    models = {
        u'cspreporting.cspreport': {
            'Meta': {'object_name': 'CSPReport'},
            'bid_public': ('django.db.models.fields.CharField', [], {'max_length': '37', 'null': 'True', 'blank': 'True'}),
            'blocked_uri': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            'column_number': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'csp_raw': ('django.db.models.fields.TextField', [], {}),
            'document_uri': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'line_number': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'referrer': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            'reported_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'source_file': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            'status_code': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'violated_directive': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'})
        }
    }

    complete_apps = ['cspreporting']