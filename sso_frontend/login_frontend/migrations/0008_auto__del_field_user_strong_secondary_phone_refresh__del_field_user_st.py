# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Deleting field 'User.strong_secondary_phone_refresh'
        db.delete_column(u'login_frontend_user', 'strong_secondary_phone_refresh')

        # Deleting field 'User.strong_secondary_phone'
        db.delete_column(u'login_frontend_user', 'strong_secondary_phone')

        # Deleting field 'User.strong_primary_phone'
        db.delete_column(u'login_frontend_user', 'strong_primary_phone')

        # Deleting field 'User.strong_primary_phone_changed'
        db.delete_column(u'login_frontend_user', 'strong_primary_phone_changed')

        # Deleting field 'User.strong_primary_phone_refresh'
        db.delete_column(u'login_frontend_user', 'strong_primary_phone_refresh')

        # Adding field 'User.primary_phone_changed'
        db.add_column(u'login_frontend_user', 'primary_phone_changed',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)

        # Adding field 'User.email'
        db.add_column(u'login_frontend_user', 'email',
                      self.gf('django.db.models.fields.EmailField')(max_length=75, null=True, blank=True),
                      keep_default=False)

        # Adding field 'User.primary_phone'
        db.add_column(u'login_frontend_user', 'primary_phone',
                      self.gf('django.db.models.fields.CharField')(max_length=30, unique=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'User.secondary_phone'
        db.add_column(u'login_frontend_user', 'secondary_phone',
                      self.gf('django.db.models.fields.CharField')(max_length=30, unique=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'User.primary_phone_refresh'
        db.add_column(u'login_frontend_user', 'primary_phone_refresh',
                      self.gf('django.db.models.fields.DateTimeField')(null=True),
                      keep_default=False)

        # Adding field 'User.secondary_phone_refresh'
        db.add_column(u'login_frontend_user', 'secondary_phone_refresh',
                      self.gf('django.db.models.fields.DateTimeField')(null=True),
                      keep_default=False)


    def backwards(self, orm):
        # Adding field 'User.strong_secondary_phone_refresh'
        db.add_column(u'login_frontend_user', 'strong_secondary_phone_refresh',
                      self.gf('django.db.models.fields.DateTimeField')(null=True),
                      keep_default=False)

        # Adding field 'User.strong_secondary_phone'
        db.add_column(u'login_frontend_user', 'strong_secondary_phone',
                      self.gf('django.db.models.fields.CharField')(unique=True, max_length=30, null=True, blank=True),
                      keep_default=False)

        # Adding field 'User.strong_primary_phone'
        db.add_column(u'login_frontend_user', 'strong_primary_phone',
                      self.gf('django.db.models.fields.CharField')(unique=True, max_length=30, null=True, blank=True),
                      keep_default=False)

        # Adding field 'User.strong_primary_phone_changed'
        db.add_column(u'login_frontend_user', 'strong_primary_phone_changed',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)

        # Adding field 'User.strong_primary_phone_refresh'
        db.add_column(u'login_frontend_user', 'strong_primary_phone_refresh',
                      self.gf('django.db.models.fields.DateTimeField')(null=True),
                      keep_default=False)

        # Deleting field 'User.primary_phone_changed'
        db.delete_column(u'login_frontend_user', 'primary_phone_changed')

        # Deleting field 'User.email'
        db.delete_column(u'login_frontend_user', 'email')

        # Deleting field 'User.primary_phone'
        db.delete_column(u'login_frontend_user', 'primary_phone')

        # Deleting field 'User.secondary_phone'
        db.delete_column(u'login_frontend_user', 'secondary_phone')

        # Deleting field 'User.primary_phone_refresh'
        db.delete_column(u'login_frontend_user', 'primary_phone_refresh')

        # Deleting field 'User.secondary_phone_refresh'
        db.delete_column(u'login_frontend_user', 'secondary_phone_refresh')


    models = {
        u'login_frontend.browser': {
            'Meta': {'object_name': 'Browser'},
            'auth_level': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '2', 'decimal_places': '0'}),
            'auth_level_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'auth_state': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '2', 'decimal_places': '0'}),
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
            'auth_timestamp': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'max_auth_level': ('django.db.models.fields.CharField', [], {'default': '0', 'max_length': '1'}),
            'username': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.user': {
            'Meta': {'object_name': 'User'},
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'null': 'True', 'blank': 'True'}),
            'primary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'primary_phone_changed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'primary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'secondary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'secondary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'strong_authy_id': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_configured': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_sms_always': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '50', 'primary_key': 'True'})
        }
    }

    complete_apps = ['login_frontend']