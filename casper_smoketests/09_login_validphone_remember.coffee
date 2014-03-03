phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index', "Redirected to password authentication"
    @.test.assertHttpStatus 200
   @.viewport(1200, 1200)
   @.then ->
    @.echo("Check remember me")
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)

   @.then ->
    @.test.assertHttpStatus 200, "Authenticated with username and password"

   @.thenOpen("http://localhost:8000/index")
   @.then ->
    @.test.assertSelectorHasText "p",  "You are remembered on this browser."

   @.then ->
    phantom.deleteCookie("v2sessionbid")

   @.thenOpen("http://localhost:8000/sessions")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/sessions', "Properly redirected to SMS after session id was removed"

   @.then ->
    @.echo "Sign out"
    @.clickLabel("Sign out")

   @.thenOpen("http://localhost:8000")
   @.then ->
    @.echo("Check remember me")
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)

   @.then ->
    @.echo("Check remember me")
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200

   @.thenOpen("http://localhost:8000/index")
   @.then ->
    @.test.assertSelectorHasText "p", "You will be signed out when you close the browser."

   @.then ->
    @.clickLabel("Sign out")


   @.thenOpen("http://localhost:8000")
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)

   @.then ->
    @.echo("Check remember me")
    @.click("input[name='my_computer']")
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200

   @.thenOpen("http://localhost:8000/index")
   @.then ->
    @.test.assertSelectorHasText "p", "You are remembered on this browser."



casper.run ->
  @.test.done()
