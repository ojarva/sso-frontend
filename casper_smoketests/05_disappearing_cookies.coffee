phantom.clearCookies()

check_cookie = (cookie_name) ->
  cookies = (phantom.cookies[cookie].name for cookie of phantom.cookies)
  return cookie_name in cookies

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assert(check_cookie "v2public-browserid")
    @.test.assert(check_cookie "v2browserid")
    @.test.assert(check_cookie "v2sessionbid")
    @.test.assert(check_cookie "csrftoken")
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
   @.viewport(1200, 1200);
   @.then ->
    phantom.deleteCookie("csrftoken")
   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(403);
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText("h1", "Oops.")
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assert(check_cookie "v2public-browserid")
    @.test.assert(check_cookie "v2browserid")
    @.test.assert(check_cookie "v2sessionbid")
    @.test.assert(check_cookie "csrftoken")
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'

   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index'

   @.then ->
    phantom.deleteCookie("v2sessionbid")
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assert(check_cookie "v2public-browserid")
    @.test.assert(check_cookie "v2browserid")
    @.test.assert(check_cookie "v2sessionbid")
    @.test.assert(check_cookie "csrftoken")
    @.test.assertSelectorHasText(".alert-info", "According to our records")

   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    phantom.deleteCookie("v2public-browserid")
   @.thenOpen('http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index')
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assert(check_cookie "v2public-browserid")

casper.run ->
  @.test.done()
