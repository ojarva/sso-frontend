casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
   @.viewport(1200, 1200);
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "1234"
    }, true);
   @.then ->
    @.test.assertSelectorHasText('.alert', 'Incorrect one-time code. Only code from message with id');
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText('.skip_for_now', 'Skip for now');
    @.test.assertSelectorHasText('.configure_authenticator_btn', 'Configure Google Authenticator');
   @.then ->
    @.clickLabel("Configure Google Authenticator")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure_authenticator?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    @.test.assertHttpStatus(200)
   @.then ->
    @.clickLabel("Sign out")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/logout?logout=on'
   @.then ->
    @.test.assertSelectorHasText('.alert-success', 'You are now signed out.')

   @.then ->
    @.clickLabel("sign in again")
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    @.test.assertSelectorHasText('.alert-warning', 'You generated Authenticator configuration, but have not used it.')
   @.then ->
    @.clickLabel("proceed to Authenticator page")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/authenticator?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    @.test.assertSelectorHasText('.alert-info', 'You have Authenticator generated')
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "asdf"
    }, true);
   @.then ->
    @.test.assertSelectorHasText(".alert-danger", "Incorrect OTP code.")
   


casper.run ->
  @.test.done()
