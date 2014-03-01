phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index', "Redirected to password authentication"
    @.test.assertHttpStatus 200
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form", {
     "username": "test",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index', "Redirected to SMS authentication page"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText '.alert', 'No phone number available.', "No phone number available is shown"
   @.then ->
    @.clickLabel "Sign out"
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/logout?logout=on', "Redirected to sign out page"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText '.alert-success', 'You are now signed out.', "Successfully signed out"

casper.run ->
  @.test.done()
