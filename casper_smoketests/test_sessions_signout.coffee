phantom.clearCookies()

signed_in_cookies = false;
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
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    signed_in_cookies = JSON.stringify(phantom.cookies)
    phantom.clearCookies();
    @.echo "Cleared cookies"
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
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
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    phantom.clearCookies();
    @.echo "Cleared cookies"
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
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
    @.click("#sessions_link")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/sessions'
   @.then ->
    @.clickLabel("Sign out all my sessions")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/sessions'
    @.test.assertDoesntExist("button:contains('Sign out all my sessions')")
    @.test.assertSelectorHasText('.alert-success', 'Signed out browser')
   @.then ->
    @.echo "Loading cookies"
    phantom.cookies = JSON.parse(signed_in_cookies)
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText('.alert-warning', 'You - or administrator - remotely signed out this browser. Please sign in again.')


casper.run ->
  @.test.done()
