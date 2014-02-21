# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'CSPReport'
        db.create_table(u'cspreporting_cspreport', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('username', self.gf('django.db.models.fields.CharField')(max_length=100)),
            ('bid_public', self.gf('django.db.models.fields.CharField')(max_length=37)),
            ('csp_raw', self.gf('django.db.models.fields.TextField')()),
            ('document_uri', self.gf('django.db.models.fields.CharField')(max_length=2000, null=True, blank=True)),
            ('referrer', self.gf('django.db.models.fields.CharField')(max_length=2000, null=True, blank=True)),
            ('violated_directive', self.gf('django.db.models.fields.CharField')(max_length=2000, null=True, blank=True)),
            ('blocked_uri', self.gf('django.db.models.fields.CharField')(max_length=2000, null=True, blank=True)),
            ('source_file', self.gf('django.db.models.fields.CharField')(max_length=2000, null=True, blank=True)),
            ('line_number', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('column_number', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('status_code', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
        ))
        db.send_create_signal(u'cspreporting', ['CSPReport'])


    def backwards(self, orm):
        # Deleting model 'CSPReport'
        db.delete_table(u'cspreporting_cspreport')


    models = {
        u'cspreporting.cspreport': {
            'Meta': {'object_name': 'CSPReport'},
            'bid_public': ('django.db.models.fields.CharField', [], {'max_length': '37'}),
            'blocked_uri': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            'column_number': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'csp_raw': ('django.db.models.fields.TextField', [], {}),
            'document_uri': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'line_number': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'referrer': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            'source_file': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'}),
            'status_code': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'violated_directive': ('django.db.models.fields.CharField', [], {'max_length': '2000', 'null': 'True', 'blank': 'True'})
        }
    }

    complete_apps = ['cspreporting']