phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Properly redirected to password authentication"
    @.test.assertHttpStatus 200
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_admin",
     "password": "testpassword"
    }, true);
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index', 'Redirected to SMS authentication'
    @.test.assertHttpStatus 200
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true);
   @.then ->
    @.test.assertHttpStatus 200, "Authentication succeeded"

   @.thenOpen("http://localhost:8000/view-csp-warnings")
   @.then ->
    @.test.assertUrlMatch "http://localhost:8000/view-csp-warnings", "CSP warnings page opened"
    @.test.assertHttpStatus 200
   @.thenOpen("http://localhost:8000/test-csp")
   @.then ->
    @.test.assertUrlMatch "http://localhost:8000/test-csp", "CSP testing page opened"
    @.test.assertHttpStatus 200
   @.thenOpen("http://localhost:8000/view-csp-reports")
   @.then ->
    @.test.assertUrlMatch "http://localhost:8000/view-csp-report", "Personal CSP reports page opened"
    @.test.assertHttpStatus 200

   @.thenOpen("http://localhost:8000/csp-report")
   @.then ->
    @.test.assertUrlMatch "http://localhost:8000/csp-report", "CSP report page opened"
    @.test.assertHttpStatus 200
   
   @.then ->
    @.open('http://localhost:8000/csp-report', {
       method: 'post', 
       data: '{"csp-report":{"document-uri":"http://localhost:8000/second/sms?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","referrer":"http://localhost:8000/first/password?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","violated-directive":"style-src \'self\'","original-policy":"default-src \'none\'; connect-src \'self\'; script-src \'self\'; img-src \'self\'; style-src \'self\'; report-uri /csp-report; font-src \'self\'","blocked-uri":"","source-file":"chrome-extension://cfhdojbkjhnklbpkdaibdccddilifddb","line-number":37,"column-number":47,"status-code":0}}'
    })
   @.then ->
    @.test.assertHttpStatus 200, "Successfully posted CSP report"
   @.then ->
    @.open('http://localhost:8000/csp-report', {
       method: 'post', 
       data: '{"csp-report":{"document-uri":"http://localhost:8000/second/sms?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","referrer":"http://localhost:8000/first/password?_sso=pubtkt&back=https%3A%2F%2Ftestservice.example.com%2F","violated-directive":"style-src \'self\'","original-policy":"default-src \'none\'; connect-src \'self\'; script-src \'self\'; img-src \'self\'; style-src \'self\'; report-uri /csp-report; font-src \'self\'","blocked-uri":"","source-file":"http://localhost:8000/testsite","line-number":37,"column-number":47,"status-code":0}}'
    })
   @.thenOpen("http://localhost:8000/view-csp-warnings")
   @.then ->
    @.capture("screenshots_csp_warnings.png")
    @.test.assertSelectorHasText "td", "http://localhost:8000/testsite", "CSP report was recorded personal report"
    @.test.assertHttpStatus 200

   @.thenOpen("http://localhost:8000/view-csp-reports")
   @.then ->
    @.capture("screenshots_csp_reports.png")
    @.test.assertSelectorHasText "td", "http://localhost:8000/testsite", "CSP report was recorded to warnings"
    @.test.assertSelectorHasText "td", "None (browser extension)", "Browser extension was detected properly"
    @.test.assertHttpStatus 200

casper.run ->
  @.test.done()
