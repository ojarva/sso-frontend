phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
    @.then ->
        @.test.assertHttpStatus 200
    @.viewport(1200, 1200)
    @.then ->
        @.fill("form[name='loginform']", {
            "username": "test_valid",
            "password": "testpassword"
        }, true);
    @.then ->
        @.clickLabel("Authenticate with SMS")
    @.then ->
        @.fill("form[name='loginform']", {
            "otp": "12345"
        }, true);
    @.then ->
        @.test.assertHttpStatus 200
        @.test.assertUrlMatch "http://localhost:8000/name_your_browser?_sso=internal&_sc=on&next=/index", "Asking for browser name"
    @.thenOpen("http://localhost:8000/data")
    @.then ->
        @.capture("screenshots_datacollection_signed_in.png")
        @.test.assertUrlMatch 'http://localhost:8000/data', "Opened data collection page (signed in)"
        @.test.assertHttpStatus 200

    @.then ->
        phantom.clearCookies()
    @.thenOpen("http://localhost:8000/data")
    @.then ->
        @.capture("screenshots_datacollection_not_signed_in.png")
        @.test.assertUrlMatch 'http://localhost:8000/data', "Opened data collection page (signed in)"
        @.test.assertHttpStatus 200


casper.run ->
  @.test.done()
