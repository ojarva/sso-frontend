phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Redirected to password authentication"
    @.test.assertHttpStatus 200
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form", {
     "username": "wrong_username"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "No redirect after incorrect credentials"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText '.alert-warning', 'Please enter both username and password.', "Prompt for username and password"

   @.then ->
    @.fill("form", {
     "password": "wrong_password"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "No redirect after incorrect credentials"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText '.alert-warning', 'Please enter both username and password.', "Prompt for username and password"

casper.run ->
  @.test.done()
