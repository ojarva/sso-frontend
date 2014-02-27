phantom.clearCookies()

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
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertHttpStatus(200)
   @.thenOpen("http://localhost:8000/view-csp-warnings")
   @.then ->
    @.test.assertHttpStatus(200)
   @.thenOpen("http://localhost:8000/test-csp")
   @.then ->
    @.test.assertHttpStatus(200)
   @.thenOpen("http://localhost:8000/view-csp-reports")
   @.then ->
    @.test.assertHttpStatus(200)

   @.thenOpen("http://localhost:8000/csp-report")
   @.then ->
    @.test.assertHttpStatus(200)
   
   @.then ->
    @.open('http://localhost:8000/csp-report', {
       method: 'post', 
       data: '{"csp-report":{"document-uri":"http://localhost:8000/second/sms?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","referrer":"http://localhost:8000/first/password?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","violated-directive":"style-src \'self\'","original-policy":"default-src \'none\'; connect-src \'self\'; script-src \'self\'; img-src \'self\'; style-src \'self\'; report-uri /csp-report; font-src \'self\'","blocked-uri":"","source-file":"chrome-extension://cfhdojbkjhnklbpkdaibdccddilifddb","line-number":37,"column-number":47,"status-code":0}}'
    })
   @.then ->
    @.test.assertHttpStatus(200)
   @.then ->
    @.open('http://localhost:8000/csp-report', {
       method: 'post', 
       data: '{"csp-report":{"document-uri":"http://localhost:8000/second/sms?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","referrer":"http://localhost:8000/first/password?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","violated-directive":"style-src \'self\'","original-policy":"default-src \'none\'; connect-src \'self\'; script-src \'self\'; img-src \'self\'; style-src \'self\'; report-uri /csp-report; font-src \'self\'","blocked-uri":"","source-file":"http://localhost:8000/testsite","line-number":37,"column-number":47,"status-code":0}}'
    })
   @.thenOpen("http://localhost:8000/view-csp-warnings")
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assertSelectorHasText("td", "http://localhost:8000/testsite") 

   @.thenOpen("http://localhost:8000/view-csp-reports")
   @.then ->
    @.test.assertHttpStatus(200)
    @.test.assertSelectorHasText("td", "http://localhost:8000/testsite")
    @.test.assertSelectorHasText("td", "None (browser extension)")

casper.run ->
  @.test.done()
