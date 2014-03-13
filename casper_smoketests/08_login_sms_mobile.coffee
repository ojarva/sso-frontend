phantom.clearCookies()

casper.on "http.status.301", (resource) ->
    @echo "#{resource.url} is permanently redirected", "PARAMETER"

casper.on "http.status.404", (resource) ->
    @echo "#{resource.url} is not found", "COMMENT"

casper.on "http.status.500", (resource) ->
    @echo "#{resource.url} is in error", "ERROR"

casper.userAgent('Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.1')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Redirected to password authentication"
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index', "Redirected to SMS authentication"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "1234"
    }, true)
   @.then ->
    @.capture("screenshots_sms_invalid.png")
    @.test.assertSelectorHasText '.alert', 'Incorrect one-time code. Only code from message with id', "Incorrect OTP warning"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.capture("screenshots_configuration.png")
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=/index', "Redirected to configuration view"
    @.test.assertSelectorHasText('.skip_for_now', 'Skip for now', "Skip for now is available")
    @.test.assertSelectorHasText('.configure_authenticator_btn', 'Configure Google Authenticator', "Configure google authenticator is available")

casper.run ->
  @.test.done()
