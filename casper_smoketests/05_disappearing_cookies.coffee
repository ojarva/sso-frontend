phantom.clearCookies()

check_cookie = (cookie_name) ->
  cookies = (phantom.cookies[cookie].name for cookie of phantom.cookies)
  return cookie_name in cookies

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index', "Properly redirected to password authentication"
    @.test.assertHttpStatus 200
    @.test.assert(check_cookie "v2public-browserid", "Browser public ID cookie")
    @.test.assert(check_cookie "v2browserid", "Browser ID cookie")
    @.test.assert(check_cookie "v2sessionbid", "Session cookie")
    @.test.assert(check_cookie "csrftoken", "CSRF token cookie")
   @.viewport(1200, 1200)
   @.then ->
    phantom.deleteCookie("csrftoken")
   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertSelectorHasText "h1", "Oops.", "CSRF error detected"
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
    @.test.assertHttpStatus(403)
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index', "Properly redirected to password authentication"
    @.test.assertHttpStatus 200
    @.test.assert(check_cookie "v2public-browserid", "Browser public ID cookie")
    @.test.assert(check_cookie "v2browserid", "Browser ID cookie")
    @.test.assert(check_cookie "v2sessionbid", "Session cookie")
    @.test.assert(check_cookie "csrftoken", "CSRF token cookie")

   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index', "Redirected to SMS authentication"
    @.test.assertHttpStatus 200

   @.then ->
    phantom.deleteCookie("v2sessionbid")
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertSelectorHasText(".alert-info", "According to our records", "Browser restart detected properly")
    @.test.assertHttpStatus 200
    @.test.assert(check_cookie "v2public-browserid", "Browser public ID cookie")
    @.test.assert(check_cookie "v2browserid", "Browser ID cookie")
    @.test.assert(check_cookie "v2sessionbid", "Session cookie")
    @.test.assert(check_cookie "csrftoken", "CSRF token cookie")

   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index', "Redirected to SMS authentication"
    @.test.assertHttpStatus 200
   @.then ->
    @.echo("Delete public browserid")
    phantom.deleteCookie("v2public-browserid")
   @.thenOpen('http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index')
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assert(check_cookie "v2public-browserid", "Browser public ID cookie")
    @.test.assert(check_cookie "v2browserid", "Browser ID cookie")
    @.test.assert(check_cookie "v2sessionbid", "Session cookie")
    @.test.assert(check_cookie "csrftoken", "CSRF token cookie")

casper.run ->
  @.test.done()
