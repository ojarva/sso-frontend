phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus 200
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Redirected to password authentication"
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid2",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index', "Redirected to SMS authentication"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=/index', "Redirected to configuration view"
   @.then ->
    @.clickLabel("Configure Google Authenticator")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure_authenticator?_sso=internal&next=/index', "Entered authenticator configuration"
    @.test.assertHttpStatus 200
   @.then ->
    @.clickLabel("Sign out")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/logout?logout=on'
    @.test.assertSelectorHasText('.alert-success', 'You are now signed out.', "Signed out message")

   @.then ->
    @.clickLabel("sign in again")
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid2",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index'
    @.test.assertSelectorHasText('.alert-warning', 'You generated Authenticator configuration, but have not used it.', "Authenticator generated but not used warning")
   @.then ->
    @.clickLabel("proceed to Authenticator page")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/authenticator?_sso=internal&next=/index', "Entered Authenticator page"
    @.test.assertSelectorHasText('.alert-info', 'You have Authenticator generated', "Authenticator generated but not used warning")
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "asdf"
    }, true)
   @.then ->
    @.test.assertSelectorHasText(".alert-danger", "Incorrect OTP code.", "Incorrect OTP for authenticator")
   


casper.run ->
  @.test.done()
