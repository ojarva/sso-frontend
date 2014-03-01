phantom.clearCookies()

casper.start 'http://localhost:8000/', ->
   @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=http://localhost:8000/index', "Redirected properly to first step authentication"
   @.test.assertHttpStatus 200
 
casper.run ->
  @.test.done()
