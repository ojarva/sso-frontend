phantom.clearCookies()
casper.userAgent('Wget/1.13.4 (linux-gnu)')
casper.start 'http://localhost:8000/', ->
   @.viewport(1200, 1200)
   @.then ->
    @.capture("screenshots_bots.png")
    @.test.assertUrlMatch 'http://localhost:8000', "wget was not redirected"
    @.test.assertHttpStatus 200
    @.test.assertSelectorHasText(".alert-danger", "It seems you are a bot", "Bot warning is shown")
 
casper.run ->
  @.test.done()

