from django import forms

class OTPForm(forms.Form):
    otp = forms.CharField(label='OTP')

class AuthWithPasswordForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Username'}), label='')
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Password'}), label='')
    
