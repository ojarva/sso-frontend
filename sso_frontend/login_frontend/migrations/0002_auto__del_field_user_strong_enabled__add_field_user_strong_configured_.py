# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Deleting field 'User.strong_enabled'
        db.delete_column(u'login_frontend_user', 'strong_enabled')

        # Adding field 'User.strong_configured'
        db.add_column(u'login_frontend_user', 'strong_configured',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)

        # Adding field 'User.strong_authy_id'
        db.add_column(u'login_frontend_user', 'strong_authy_id',
                      self.gf('django.db.models.fields.CharField')(max_length=30, null=True, blank=True),
                      keep_default=False)

        # Adding unique constraint on 'User', fields ['strong_phone']
        db.create_unique(u'login_frontend_user', ['strong_phone'])

        # Deleting field 'BrowserUsers.current_auth_level'
        db.delete_column(u'login_frontend_browserusers', 'current_auth_level')


    def backwards(self, orm):
        # Removing unique constraint on 'User', fields ['strong_phone']
        db.delete_unique(u'login_frontend_user', ['strong_phone'])

        # Adding field 'User.strong_enabled'
        db.add_column(u'login_frontend_user', 'strong_enabled',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)

        # Deleting field 'User.strong_configured'
        db.delete_column(u'login_frontend_user', 'strong_configured')

        # Deleting field 'User.strong_authy_id'
        db.delete_column(u'login_frontend_user', 'strong_authy_id')

        # Adding field 'BrowserUsers.current_auth_level'
        db.add_column(u'login_frontend_browserusers', 'current_auth_level',
                      self.gf('django.db.models.fields.CharField')(default='0', max_length=1),
                      keep_default=False)


    models = {
        u'login_frontend.browser': {
            'Meta': {'object_name': 'Browser'},
            'auth_level': ('django.db.models.fields.CharField', [], {'default': '0', 'max_length': '1'}),
            'auth_level_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'auth_state': ('django.db.models.fields.CharField', [], {'default': '0', 'max_length': '1'}),
            'auth_state_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'bid': ('django.db.models.fields.CharField', [], {'max_length': '37', 'primary_key': 'True'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'save_browser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'ua': ('django.db.models.fields.CharField', [], {'max_length': '250'}),
            'username': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']", 'null': 'True'})
        },
        u'login_frontend.browserusers': {
            'Meta': {'object_name': 'BrowserUsers'},
            'auth_timestamp': ('django.db.models.fields.DateTimeField', [], {}),
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'max_auth_level': ('django.db.models.fields.CharField', [], {'default': '0', 'max_length': '1'}),
            'username': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.user': {
            'Meta': {'object_name': 'User'},
            'strong_authy_id': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_configured': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '50', 'primary_key': 'True'})
        }
    }

    complete_apps = ['login_frontend']