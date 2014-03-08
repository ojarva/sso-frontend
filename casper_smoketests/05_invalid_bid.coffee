phantom.clearCookies()

check_cookie = (cookie_name) ->
  cookies = (phantom.cookies[cookie].name for cookie of phantom.cookies)
  return cookie_name in cookies

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Redirected to password authentication"
    @.test.assertHttpStatus 200
    @.test.assertTrue(check_cookie "v2public-browserid", "Browser public ID cookie")
    @.test.assertTrue(check_cookie "v2browserid", "Browser ID cookie")
    @.test.assertTrue(check_cookie "v2sessionbid", "Session cookie")
    @.test.assertTrue(check_cookie "csrftoken", "CSRF token cookie")
   @.then ->
    @.echo("Set invalid v2browserid")
    phantom.deleteCookie("v2browserid")
    phantom.addCookie({
     name: "v2browserid",
     value: "invalid browser id",
     domain: "localhost"
    })
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Properly redirected to password authentication"
    @.test.assertHttpStatus 200
    @.test.assertTrue(check_cookie "v2public-browserid", "Browser public ID cookie")
    @.test.assertTrue(check_cookie "v2browserid", "Browser ID cookie set again")
    @.test.assertTrue(check_cookie "v2sessionbid", "Session cookie")
    @.test.assertTrue(check_cookie "csrftoken", "CSRF token cookie")

casper.run ->
  @.test.done()
