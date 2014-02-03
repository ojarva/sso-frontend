# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Log'
        db.create_table(u'login_frontend_log', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.User'])),
            ('timestamp', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('remote_ip', self.gf('django.db.models.fields.CharField')(max_length=47, null=True, blank=True)),
            ('message', self.gf('django.db.models.fields.TextField')()),
        ))
        db.send_create_signal(u'login_frontend', ['Log'])

        # Adding field 'User.strong_authenticator_generated_at'
        db.add_column(u'login_frontend_user', 'strong_authenticator_generated_at',
                      self.gf('django.db.models.fields.DateTimeField')(null=True),
                      keep_default=False)


    def backwards(self, orm):
        # Deleting model 'Log'
        db.delete_table(u'login_frontend_log')

        # Deleting field 'User.strong_authenticator_generated_at'
        db.delete_column(u'login_frontend_user', 'strong_authenticator_generated_at')


    models = {
        u'login_frontend.browser': {
            'Meta': {'object_name': 'Browser'},
            'auth_level': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '2', 'decimal_places': '0'}),
            'auth_level_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'auth_state': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '2', 'decimal_places': '0'}),
            'auth_state_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'authenticator_qr_nonce': ('django.db.models.fields.CharField', [], {'max_length': '37', 'null': 'True', 'blank': 'True'}),
            'bid': ('django.db.models.fields.CharField', [], {'max_length': '37', 'primary_key': 'True'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'save_browser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'sms_code': ('django.db.models.fields.CharField', [], {'max_length': '10', 'null': 'True', 'blank': 'True'}),
            'sms_code_generated_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'sms_code_id': ('django.db.models.fields.CharField', [], {'max_length': '5', 'null': 'True', 'blank': 'True'}),
            'ua': ('django.db.models.fields.CharField', [], {'max_length': '250'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']", 'null': 'True'})
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
        u'login_frontend.log': {
            'Meta': {'object_name': 'Log'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'message': ('django.db.models.fields.TextField', [], {}),
            'remote_ip': ('django.db.models.fields.CharField', [], {'max_length': '47', 'null': 'True', 'blank': 'True'}),
            'timestamp': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.usedotp': {
            'Meta': {'object_name': 'UsedOTP'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '15'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'used_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'used_from': ('django.db.models.fields.CharField', [], {'max_length': '46', 'null': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.user': {
            'Meta': {'object_name': 'User'},
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'null': 'True', 'blank': 'True'}),
            'primary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'primary_phone_changed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'primary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'secondary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'secondary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'strong_authenticator_generated_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'strong_authenticator_secret': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_authenticator_used': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_configured': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_sms_always': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_tokens': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '50', 'primary_key': 'True'})
        }
    }

    complete_apps = ['login_frontend']