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
   @.then ->
    phantom.deleteCookie("v2browserid")
    phantom.addCookie({
     name: "v2browserid",
     value: "invalid browser id",
     domain: "localhost"
    });
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assert(check_cookie "v2public-browserid")
    @.test.assert(check_cookie "v2browserid")
    @.test.assert(check_cookie "v2sessionbid")
    @.test.assert(check_cookie "csrftoken")
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'

casper.run ->
  @.test.done()
