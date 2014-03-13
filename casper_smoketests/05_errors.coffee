phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.then ->
    @.test.assertHttpStatus 200
   @.thenOpen "http://localhost:8000/errors/400"
   @.then ->
    @.capture("screenshots_400.png")
    @.test.assertHttpStatus 400, "Error 400 returned properly"
    @.test.assertSelectorHasText "h1", "Oops. Bad request", "Bad request template"
   @.thenOpen "http://localhost:8000/errors/403"
   @.then ->
    @.capture("screenshots_403.png")
    @.test.assertHttpStatus 403, "Error 403 returned properly"
    @.test.assertSelectorHasText "h1", "Oops. Unauthorized", "Unauthorized template"
# These does not work with DEBUG=True
#   @.thenOpen "http://localhost:8000/errors/404"
#   @.then ->
#    @.test.assertHttpStatus(404)
#    @.test.assertSelectorHasText("h1", "Oops. Not found")
#   @.thenOpen "http://localhost:8000/errors/500"
#   @.then ->
#    @.test.assertHttpStatus(500)
#    @.test.assertSelectorHasText("h1", "Oh snap. Internal server error.")


casper.run ->
  @.test.done()
