phantom.clearCookies()

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
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=http://localhost:8000/index'
    @.test.assertHttpStatus(200)
   @.then ->
    @.clickLabel("Always use SMS")
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assertSelectorHasText(".alert-success", "Switched to SMS authentication")
   @.then ->
    @.click(".configure_authenticator_btn")
   @.thenOpen("http://localhost:8000/configure")
   @.then ->
    @.test.assertHttpStatus(200)
   @.then ->
    @.clickLabel("Prompt for Authenticator")
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assertSelectorHasText(".alert-success", "Default setting changed to Authenticator")

   @.then ->
    @.echo "Reset cookies and try signing in again"
    phantom.clearCookies()

   @.thenOpen("http://localhost:8000")
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
    @.test.assertUrlMatch 'http://localhost:8000/second/authenticator?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    @.clickLabel("SMS authentication instead")
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assertUrlMatch 'http://localhost:8000/index'

casper.run ->
  @.test.done()
