phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.viewport(1200, 1200);
   @.then ->
    @.capture("screenshots_1f.png")
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Properly redirected to first step authentication"
    @.test.assertHttpStatus 200
   @.then ->
    @.fill("form", {
     "username": "test",
     "password": "testpassword"
    }, true)
   @.then ->
    @.capture("screenshots_2f-sms.png")
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index', "Properly authenticated and redirected to SMS auth"
    @.test.assertHttpStatus 200

casper.run ->
  @.test.done()
