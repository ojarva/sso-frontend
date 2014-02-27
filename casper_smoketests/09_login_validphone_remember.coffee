phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus(200, "Front page opened")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
   @.viewport(1200, 1200);
   @.then ->
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);

   @.then ->
    @.test.assertHttpStatus(200);
   @.then ->
    phantom.clearCookies()
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "otp": "1234"
    }, true);
   @.then ->
    @.test.assertSelectorHasText('.alert-danger', 'Incorrect one-time code. Only code from message with id');
   @.then ->
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200)

casper.run ->
  @.test.done()
