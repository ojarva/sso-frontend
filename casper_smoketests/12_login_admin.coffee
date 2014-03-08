phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Redirected to password authentication"
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_admin",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index', "Redirected to SMS authentication"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "1234"
    }, true)
   @.then ->
    @.test.assertSelectorHasText('.alert', 'Incorrect one-time code. Only code from message with id', "Incorrect OTP error")
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=/index', "Redirected to configuration view"
   @.then ->
    @.clickLabel("Admin")
   @.then ->
    @.test.assertHttpStatus 200, "Admin frontpage"
   @.then ->
    @.clickLabel("Main")
   @.then ->
    @.test.assertHttpStatus 200, "Admin frontpage"

   @.then ->
    @.clickLabel("Users")
   @.then ->
    @.test.assertHttpStatus 200, "Admin user listing"

   @.then ->
    @.clickLabel("test_admin")
   @.then ->
    @.test.assertHttpStatus 200, "Admin user page"
    @.test.assertUrlMatch 'http://localhost:8000/admin_/user/test_admin', "test_admin user page"
   @.then -> 
    @.clickLabel("Details")
   @.then ->
    @.test.assertHttpStatus 200, "Browser details page"
   @.then ->
    @.clickLabel("View logs")
   @.then ->
    @.test.assertHttpStatus 200, "Browser logs (admin) page"

   @.then ->
    @.fill("form.form-inline", 
      {"q": "test_admin"},
      true)
   @.then ->
    @.test.assertHttpStatus 200, "Search for valid user"
    @.test.assertUrlMatch 'http://localhost:8000/admin_/search?q=test_admin', "Redirected to search page"
   @.then ->
    @.clickLabel("Microsoft Internet Explorer on Windows (XP)")
   @.then ->
    @.test.assertHttpStatus 200, "Browser details page"

   @.then ->
    @.fill("form.form-inline", 
      {"q": "invalid search string"},
      true)
   @.then ->
    @.test.assertHttpStatus 200, "Search for invalid user"

   @.then ->
    @.clickLabel("Logins")
   @.then ->
    @.test.assertHttpStatus 200, "List of logins"

   @.then ->
    @.clickLabel("Browsers")
   @.then ->
    @.test.assertHttpStatus 200, "List of browsers"

   @.then ->
    @.clickLabel("Details")
   @.then ->
    @.test.assertHttpStatus 200, "Browser details"

   @.then ->
    @.clickLabel("Logs")
   @.then ->
    @.test.assertHttpStatus 200, "Log view"

   @.then ->
    @.clickLabel("test_admin")
   @.then ->
    @.test.assertHttpStatus 200, "User details for test_admin"

   @.then ->
    @.clickLabel("View all")
   @.then ->
    @.test.assertHttpStatus 200, "View all log entries for test_admin"
     


casper.run ->
  @.test.done()
