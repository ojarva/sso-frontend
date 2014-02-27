phantom.clearCookies()

casper.start 'http://localhost:8000/', ->
   @.viewport(1200, 1200);
   @.thenClick("#introduction_link")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/introduction'
   @.then ->
    @.clickLabel("separate instructions page for developers")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/developer_introduction'

casper.run ->
  @.test.done()
