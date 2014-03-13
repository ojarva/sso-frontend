phantom.clearCookies()

casper.on "http.status.301", (resource) ->
    @echo "#{resource.url} is permanently redirected", "PARAMETER"

casper.on "http.status.404", (resource) ->
    @echo "#{resource.url} is not found", "COMMENT"

casper.on "http.status.500", (resource) ->
    @echo "#{resource.url} is in error", "ERROR"

casper.userAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:26.0) Gecko/20100101 Firefox/26.0')

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
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=/index', "Redirected to configuration view"
    @.test.assertSelectorHasText('.skip_for_now', 'Skip for now', "Skip for now is available")
    @.test.assertSelectorHasText('.configure_authenticator_btn', 'Configure Google Authenticator', "Configure google authenticator is available")
   @.then ->
    @.echo "Upgrading UA"
    casper.userAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:26.0) Gecko/20100101 Firefox/26.0')
   @.thenOpen("http://localhost:8000/sessions")
   @.then ->
    @.capture("screenshots_additional_auth.png")
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/sessions', 'Redirected to password authentication'
    @.test.assertSelectorHasText('.alert-success', 'Additional authentication is required')
   @.then ->
    @.fill("form[name='loginform']", {
     "password": "testpassword"
    }, true)
   @.then ->
    @.capture("screenshots_sessions.png")
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/sessions', 'Redirected to sessions'
   @.then ->
    @.echo "Downgrade user agent"
    casper.userAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:26.0) Gecko/20100101 Firefox/26.0')
   @.thenOpen("http://localhost:8000/sessions")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/sessions', 'Redirected to password authentication'
    @.test.assertSelectorHasText('.alert-warning', 'It seems your browser or OS was downgraded')
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/sessions', "Redirected to SMS authentication"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=/sessions', "Redirected to configuration view"
    @.test.assertHttpStatus 200
   @.then ->
    @.echo "Changing user agent completely"
    casper.userAgent('Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.1')
   @.thenOpen("http://localhost:8000/sessions")
   @.then ->
    @.capture("screenshots_browser_changed.png")
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/sessions', 'Redirected to password authentication'
    @.test.assertSelectorHasText('.alert-warning', 'Your browser was changed.')

casper.run ->
  @.test.done()
