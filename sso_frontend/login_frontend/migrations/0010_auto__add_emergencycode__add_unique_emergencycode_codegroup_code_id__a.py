# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'EmergencyCode'
        db.create_table(u'login_frontend_emergencycode', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('codegroup', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.EmergencyCodes'])),
            ('code_id', self.gf('django.db.models.fields.IntegerField')()),
            ('code_val', self.gf('django.db.models.fields.CharField')(max_length=20)),
        ))
        db.send_create_signal(u'login_frontend', ['EmergencyCode'])

        # Adding unique constraint on 'EmergencyCode', fields ['codegroup', 'code_id']
        db.create_unique(u'login_frontend_emergencycode', ['codegroup_id', 'code_id'])

        # Adding unique constraint on 'EmergencyCode', fields ['codegroup', 'code_val']
        db.create_unique(u'login_frontend_emergencycode', ['codegroup_id', 'code_val'])

        # Adding model 'EmergencyCodes'
        db.create_table(u'login_frontend_emergencycodes', (
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.User'], primary_key=True)),
            ('generated_at', self.gf('django.db.models.fields.DateTimeField')(null=True)),
            ('current_code', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.EmergencyCode'], null=True)),
        ))
        db.send_create_signal(u'login_frontend', ['EmergencyCodes'])

        # Adding field 'User.strong_authenticator_secret'
        db.add_column(u'login_frontend_user', 'strong_authenticator_secret',
                      self.gf('django.db.models.fields.CharField')(max_length=30, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Browser.sms_code'
        db.add_column(u'login_frontend_browser', 'sms_code',
                      self.gf('django.db.models.fields.CharField')(max_length=10, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Browser.sms_code_id'
        db.add_column(u'login_frontend_browser', 'sms_code_id',
                      self.gf('django.db.models.fields.CharField')(max_length=5, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Browser.sms_code_generated_at'
        db.add_column(u'login_frontend_browser', 'sms_code_generated_at',
                      self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True),
                      keep_default=False)


    def backwards(self, orm):
        # Removing unique constraint on 'EmergencyCode', fields ['codegroup', 'code_val']
        db.delete_unique(u'login_frontend_emergencycode', ['codegroup_id', 'code_val'])

        # Removing unique constraint on 'EmergencyCode', fields ['codegroup', 'code_id']
        db.delete_unique(u'login_frontend_emergencycode', ['codegroup_id', 'code_id'])

        # Deleting model 'EmergencyCode'
        db.delete_table(u'login_frontend_emergencycode')

        # Deleting model 'EmergencyCodes'
        db.delete_table(u'login_frontend_emergencycodes')

        # Deleting field 'User.strong_authenticator_secret'
        db.delete_column(u'login_frontend_user', 'strong_authenticator_secret')

        # Deleting field 'Browser.sms_code'
        db.delete_column(u'login_frontend_browser', 'sms_code')

        # Deleting field 'Browser.sms_code_id'
        db.delete_column(u'login_frontend_browser', 'sms_code_id')

        # Deleting field 'Browser.sms_code_generated_at'
        db.delete_column(u'login_frontend_browser', 'sms_code_generated_at')


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
            'sms_code': ('django.db.models.fields.CharField', [], {'max_length': '10', 'null': 'True', 'blank': 'True'}),
            'sms_code_generated_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'sms_code_id': ('django.db.models.fields.CharField', [], {'max_length': '5', 'null': 'True', 'blank': 'True'}),
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
        u'login_frontend.emergencycode': {
            'Meta': {'unique_together': "(('codegroup', 'code_id'), ('codegroup', 'code_val'))", 'object_name': 'EmergencyCode'},
            'code_id': ('django.db.models.fields.IntegerField', [], {}),
            'code_val': ('django.db.models.fields.CharField', [], {'max_length': '20'}),
            'codegroup': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.EmergencyCodes']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'})
        },
        u'login_frontend.emergencycodes': {
            'Meta': {'object_name': 'EmergencyCodes'},
            'current_code': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.EmergencyCode']", 'null': 'True'}),
            'generated_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']", 'primary_key': 'True'})
        },
        u'login_frontend.user': {
            'Meta': {'object_name': 'User'},
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'null': 'True', 'blank': 'True'}),
            'primary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'primary_phone_changed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'primary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'secondary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'secondary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'strong_authenticator_secret': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_authy_id': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_configured': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_sms_always': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '50', 'primary_key': 'True'})
        }
    }

    complete_apps = ['login_frontend']