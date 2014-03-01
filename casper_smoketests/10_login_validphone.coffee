phantom.clearCookies()

casper.on "http.status.301", (resource) ->
    @echo "#{resource.url} is permanently redirected", "PARAMETER"

casper.on "http.status.404", (resource) ->
    @echo "#{resource.url} is not found", "COMMENT"

casper.on "http.status.500", (resource) ->
    @echo "#{resource.url} is in error", "ERROR"

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index', "Redirected to password authentication"
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index', "Redirected to SMS authentication"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "1234"
    }, true)
   @.then ->
    @.test.assertSelectorHasText '.alert', 'Incorrect one-time code. Only code from message with id', "Incorrect OTP warning"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=http://localhost:8000/index', "Redirected to configuration view"
    @.test.assertSelectorHasText('.skip_for_now', 'Skip for now', "Skip for now is available")
    @.test.assertSelectorHasText('.configure_authenticator_btn', 'Configure Google Authenticator', "Configure google authenticator is available")
   @.then ->
    @.clickLabel("Configure Google Authenticator")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure_authenticator?_sso=internal&next=http://localhost:8000/index', "Authenticator configuration view"
    @.test.assertHttpStatus 200
   @.then ->
    @.clickLabel('continue to your originating service')
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/index', "Continue to service redirected properly"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText(".username", "test_valid", "Username set correctly")
   @.then ->
    @.click("#sessions_link")
   @.then ->
    @.test.assertHttpStatus 200, "Sessions page opened"
   @.then ->
    @.clickLabel("View log")
   @.then ->
    @.test.assertHttpStatus 200, "View log page opened"
   @.thenOpen("http://localhost:8000/index")
   @.then ->
    @.clickLabel("Remember me on this browser")
   @.then ->
    @.test.assertHttpStatus 200, "Remember me on this browser"
    @.test.assertSelectorHasText("button", "Forget this browser", "Browser marked as remembered")
    @.test.assertSelectorHasText(".alert-info", "You're now remembered on this browser", "Remembered notification shown")
   @.then ->
    @.clickLabel("Forget this browser")
   @.then ->
    @.test.assertHttpStatus 200, "Forget this browser"
    @.test.assertSelectorHasText("button", "Remember me on this browser", "Browser marked as not remembered")
    @.test.assertSelectorHasText(".alert-info", "You're no longer remembered on this browser", "Not remembered notification shown")

   @.thenOpen("http://localhost:8000/admin_/")
   @.then ->
    @.test.assertHttpStatus(403, "403 on admin")

   @.then ->
    @.clickLabel("Sign out")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/logout?logout=on', "Redirected to sign out page"
    @.test.assertHttpStatus 200, "Sign out succeeded"
    @.test.assertSelectorHasText('.alert-success', 'You are now signed out.', "Signed out notification shown")

casper.run ->
  @.test.done()
