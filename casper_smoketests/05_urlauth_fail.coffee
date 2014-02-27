phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000/urlauth/asdf', ->
   @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertSelectorHasText(".alert-danger", "Invalid request. Did you open this page on the same browser you started the authentication process")
   @.thenOpen("http://localhost:8000")
   @.then ->
    @.fill("form", {
     "username": "test_valid",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
   @.thenOpen("http://localhost:8000/urlauth/asdf")
   @.then ->
    @.test.assertSelectorHasText(".alert-danger", "Unique code for this URL expired already.")

casper.run ->
  @.test.done()
