phantom.clearCookies()

casper.start 'http://localhost:8000/', ->
   @.thenOpen "http://localhost:8000/get_pubkey/pubtkt"
   @.then ->
    @.test.assertHttpStatus 200, "Download pubtkt key"

   @.thenOpen "http://localhost:8000/get_pubkey/saml"
   @.then ->
    @.test.assertHttpStatus 200, "Download SAML key"
casper.run ->
  @.test.done()
