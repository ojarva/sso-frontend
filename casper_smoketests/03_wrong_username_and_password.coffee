phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Properly redirected to password authentication"
    @.test.assertHttpStatus 200
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form", {
     "username": "wrong_username",
     "password": "wrong_password"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "On first step authentication page"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText '.alert', 'Invalid username or password.', "Invalid username or password"

casper.run ->
  @.test.done()
