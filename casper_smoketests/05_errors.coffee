phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)');
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus(200);
   @.thenOpen "http://localhost:8000/errors/400"
   @.then ->
    @.test.assertHttpStatus(400)
    @.test.assertSelectorHasText("h1", "Oops. Bad request")
   @.thenOpen "http://localhost:8000/errors/403"
   @.then ->
    @.test.assertHttpStatus(403)
    @.test.assertSelectorHasText("h1", "Oops. Unauthorized")
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
