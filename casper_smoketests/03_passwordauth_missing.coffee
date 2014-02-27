phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
   @.viewport(1200, 1200);
   @.then ->
    @.fill("form", {
     "username": "wrong_username"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText('.alert-warning', 'Please enter both username and password.');

   @.then ->
    @.fill("form", {
     "password": "wrong_password"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText('.alert-warning', 'Please enter both username and password.');

   @.then ->
    @.fill("form", {
     "username": "wrong_username",
     "password": "wrong_password"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText('.alert-danger', 'Invalid username or password.')

  


casper.run ->
  @.test.done()
