casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index'
   @.viewport(1200, 1200);
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_admin",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=http://localhost:8000/index'
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "1234"
    }, true);
   @.then ->
    @.test.assertSelectorHasText('.alert', 'Incorrect one-time code. Only code from message with id');
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=http://localhost:8000/index'
    @.test.assertSelectorHasText('.skip_for_now', 'Skip for now');
    @.test.assertSelectorHasText('.configure_authenticator_btn', 'Configure Google Authenticator');
   @.then ->
    @.clickLabel("Admin")
   @.then ->
    @.test.assertHttpStatus(200)
   @.then ->
    @.clickLabel("Main")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("Users")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("Logins")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("Browsers")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("Details")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("Logs")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("test_admin")
   @.then ->
    @.test.assertHttpStatus(200)

   @.then ->
    @.clickLabel("View all")
   @.then ->
    @.test.assertHttpStatus(200)
     


casper.run ->
  @.test.done()
