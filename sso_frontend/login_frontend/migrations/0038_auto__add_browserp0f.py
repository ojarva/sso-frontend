# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'BrowserP0f'
        db.create_table(u'login_frontend_browserp0f', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('browser', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.Browser'])),
            ('updated_at', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('first_seen', self.gf('django.db.models.fields.DateTimeField')()),
            ('last_seen', self.gf('django.db.models.fields.DateTimeField')()),
            ('total_conn', self.gf('django.db.models.fields.IntegerField')()),
            ('uptime_sec', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('up_mod_days', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('last_nat', self.gf('django.db.models.fields.DateTimeField')()),
            ('distance', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('os_match_q', self.gf('django.db.models.fields.CharField')(max_length=1)),
            ('os_name', self.gf('django.db.models.fields.CharField')(max_length=32, null=True, blank=True)),
            ('os_flavor', self.gf('django.db.models.fields.CharField')(max_length=32, null=True, blank=True)),
            ('link_type', self.gf('django.db.models.fields.CharField')(max_length=32, null=True, blank=True)),
        ))
        db.send_create_signal(u'login_frontend', ['BrowserP0f'])


    def backwards(self, orm):
        # Deleting model 'BrowserP0f'
        db.delete_table(u'login_frontend_browserp0f')


    models = {
        u'login_frontend.authenticatorcode': {
            'Meta': {'object_name': 'AuthenticatorCode'},
            'authenticator_id': ('django.db.models.fields.CharField', [], {'default': "'undefined'", 'max_length': '30'}),
            'authenticator_secret': ('django.db.models.fields.CharField', [], {'max_length': '30'}),
            'generated_at': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.browser': {
            'Meta': {'ordering': "['-created']", 'object_name': 'Browser'},
            'auth_level': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '2', 'decimal_places': '0'}),
            'auth_level_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'auth_state': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '2', 'decimal_places': '0'}),
            'auth_state_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'authenticator_qr_nonce': ('django.db.models.fields.CharField', [], {'max_length': '37', 'null': 'True', 'blank': 'True'}),
            'bid': ('django.db.models.fields.CharField', [], {'max_length': '37', 'primary_key': 'True'}),
            'bid_public': ('django.db.models.fields.CharField', [], {'max_length': '37'}),
            'bid_session': ('django.db.models.fields.CharField', [], {'max_length': '37'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'forced_sign_out': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'save_browser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'sms_code': ('django.db.models.fields.CharField', [], {'max_length': '10', 'null': 'True', 'blank': 'True'}),
            'sms_code_generated_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'sms_code_id': ('django.db.models.fields.CharField', [], {'max_length': '5', 'null': 'True', 'blank': 'True'}),
            'ua': ('django.db.models.fields.CharField', [], {'max_length': '250'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']", 'null': 'True'})
        },
        u'login_frontend.browserdetails': {
            'Meta': {'object_name': 'BrowserDetails'},
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'performance_memory': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'performance_navigation': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'performance_performance': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'performance_timing': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'plugins': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'remote_clock_offset': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'remote_clock_time': ('django.db.models.fields.CharField', [], {'max_length': '28', 'null': 'True', 'blank': 'True'}),
            'resolution': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'timestamp': ('django.db.models.fields.DateTimeField', [], {})
        },
        u'login_frontend.browserlogin': {
            'Meta': {'ordering': "['-auth_timestamp', 'sso_provider', 'remote_service']", 'object_name': 'BrowserLogin'},
            'auth_timestamp': ('django.db.models.fields.DateTimeField', [], {}),
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            'can_logout': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'expires_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'expires_session': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'message': ('django.db.models.fields.CharField', [], {'max_length': '1000', 'null': 'True', 'blank': 'True'}),
            'remote_service': ('django.db.models.fields.CharField', [], {'max_length': '1000', 'null': 'True', 'blank': 'True'}),
            'signed_out': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'sso_provider': ('django.db.models.fields.CharField', [], {'max_length': '30'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.browserp0f': {
            'Meta': {'ordering': "['first_seen', 'last_seen']", 'object_name': 'BrowserP0f'},
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            'distance': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'first_seen': ('django.db.models.fields.DateTimeField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_nat': ('django.db.models.fields.DateTimeField', [], {}),
            'last_seen': ('django.db.models.fields.DateTimeField', [], {}),
            'link_type': ('django.db.models.fields.CharField', [], {'max_length': '32', 'null': 'True', 'blank': 'True'}),
            'os_flavor': ('django.db.models.fields.CharField', [], {'max_length': '32', 'null': 'True', 'blank': 'True'}),
            'os_match_q': ('django.db.models.fields.CharField', [], {'max_length': '1'}),
            'os_name': ('django.db.models.fields.CharField', [], {'max_length': '32', 'null': 'True', 'blank': 'True'}),
            'total_conn': ('django.db.models.fields.IntegerField', [], {}),
            'up_mod_days': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'updated_at': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'uptime_sec': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'})
        },
        u'login_frontend.browserusers': {
            'Meta': {'ordering': "['-auth_timestamp']", 'object_name': 'BrowserUsers'},
            'auth_timestamp': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_seen': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'last_seen_passive': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'max_auth_level': ('django.db.models.fields.CharField', [], {'default': '0', 'max_length': '1'}),
            'remote_ip': ('django.db.models.fields.GenericIPAddressField', [], {'max_length': '39', 'null': 'True', 'blank': 'True'}),
            'remote_ip_passive': ('django.db.models.fields.GenericIPAddressField', [], {'max_length': '39', 'null': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
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
        u'login_frontend.keystrokesequence': {
            'Meta': {'object_name': 'KeystrokeSequence'},
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']", 'null': 'True'}),
            'fieldname': ('django.db.models.fields.CharField', [], {'max_length': '1'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'resolution': ('django.db.models.fields.CharField', [], {'max_length': '30'}),
            'timestamp': ('django.db.models.fields.DateTimeField', [], {}),
            'timing': ('django.db.models.fields.TextField', [], {}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"}),
            'was_correct': ('django.db.models.fields.BooleanField', [], {})
        },
        u'login_frontend.log': {
            'Meta': {'ordering': "['-timestamp']", 'object_name': 'Log'},
            'bid_public': ('django.db.models.fields.CharField', [], {'max_length': '37', 'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'message': ('django.db.models.fields.TextField', [], {}),
            'remote_ip': ('django.db.models.fields.CharField', [], {'max_length': '47', 'null': 'True', 'blank': 'True'}),
            'status': ('django.db.models.fields.CharField', [], {'default': "'question'", 'max_length': '30'}),
            'timestamp': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.user': {
            'Meta': {'ordering': "['username']", 'object_name': 'User'},
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'null': 'True', 'blank': 'True'}),
            'emulate_legacy': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_admin': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'primary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'primary_phone_changed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'primary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'secondary_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'secondary_phone_refresh': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'strong_authenticator_generated_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'strong_authenticator_id': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_authenticator_num': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'strong_authenticator_secret': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'strong_authenticator_used': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_configured': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_skips_available': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'strong_sms_always': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_tokens': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '50', 'primary_key': 'True'})
        }
    }

    complete_apps = ['login_frontend']