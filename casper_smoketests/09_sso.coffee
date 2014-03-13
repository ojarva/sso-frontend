phantom.clearCookies()

casper.userAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
casper.start 'http://localhost:8000', ->
   @.test.assertHttpStatus 200
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=internal&next=/index', "Properly redirected to password authentication"
   @.viewport(1200, 1200)
   @.then ->
    @.fill("form[name='loginform']", {
     "username": "test_valid",
     "password": "testpassword"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/second/sms?_sso=internal&next=/index', "Redirected to SMS authentication"
   @.then ->
    @.fill("form[name='loginform']", {
     "otp": "12345"
    }, true)
   @.then ->
    @.test.assertHttpStatus 200
    @.test.assertUrlMatch 'http://localhost:8000/configure?_sso=internal&next=/index', "Redirected to configuration page"
   @.thenOpen("http://localhost:8000/openid/")
   @.then ->
    @.capture("screenshots_openid_main.png")
    @.test.assertHttpStatus 200
    @.test.assertField('openid_identifier', 'https://localhost:8000/openid/test_valid', "Proper openid identifier generated")
   @.thenOpen("http://localhost:8000/openid/test_valid")
   @.then ->    
    @.test.assertHttpStatus 200, "OpenID identifier page opened"
   @.thenOpen("http://localhost:8000/openid/?openid.assoc_handle=%7BHMAC-SHA1%7D%7B5309f4f9%7D%7BcYLgyA%3D%3D%7D&openid.claimed_id=http%3A%2F%2Flocalhost:8000%2Fopenid%2Ftest_valid&openid.identity=http%3A%2F%2Flocalhost:8000%2Fopenid%2Ftest_valid&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.pape.preferred_auth_policies=http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor-physical+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fphishing-resistant&openid.realm=http%3A%2F%2Fopenid-consumer.appspot.com&openid.return_to=http%3A%2F%2Fopenid-consumer.appspot.com%2Ffinish%3Fsession_id%3D3758021%26janrain_nonce%3D2014-02-27T14%253A17%253A46ZKfCLSy&openid.sreg.optional=nickname%2Cfullname%2Cemail")
   @.then ->
    @.test.assertHttpStatus 200, "OpenID request processed"

   @.thenOpen("http://localhost:8000/idp/login/")
   @.then ->
    @.capture("screenshots_saml_main.png")
    @.test.assertHttpStatus 200, "SAML frontpage opened"
    @.test.assertSelectorHasText(".alert-danger", "Incomplete request: missing SAMLRequest or RelayState argument. Aborting.", "Error message for incorrect SAML request shown")

   @.thenOpen("http://localhost:8000/idp/metadata/xml/")
   @.then ->
    @.test.assertHttpStatus 200, "SAML metadata XML"

   @.thenOpen("http://localhost:8000/?back=asdf")
   @.then ->
    @.capture("screenshots_pubtkt_invalid_return.png")
    @.test.assertHttpStatus 200, "pubtkt with invalid return url"
    @.test.assertUrlMatch 'http://localhost:8000/pubtkt?back=asdf', "Redirected to pubtkt provider"
    @.test.assertSelectorHasText("p", 'Requested service URL "asdf" is invalid', "Invalid return url error")

   @.thenOpen("http://localhost:8000/?back=https://asdf")
   @.then ->
    @.capture("screenshots_pubtkt_invalid_return2.png")
    @.test.assertHttpStatus 200, "pubtkt with invalid return url but proper schema"
    @.test.assertUrlMatch 'http://localhost:8000/pubtkt?back=https://asdf', "Redirected to pubtkt provider"
    @.test.assertSelectorHasText("p", 'Requested service URL "https://asdf" is invalid', "Invalid return url error")

   @.thenOpen("http://localhost:8000/?back=https://asdf.example.com")
   @.then ->
    @.capture("screenshots_pubtkt_invalid_return3.png")
    @.test.assertHttpStatus 200, "pubtkt with incorrect, but complete return url"
    @.test.assertUrlMatch 'http://localhost:8000/pubtkt?back=https://asdf.example.com', "Redirected to pubtkt provider"
    @.test.assertSelectorHasText("p", 'Requested service URL "https://asdf.example.com" is invalid', "Invalid return url error")

   @.thenOpen("http://localhost:8000/?back=https://")
   @.then ->
    @.capture("screenshots_pubtkt_invalid_return4.png")
    @.test.assertHttpStatus 200, "pubtkt with only schema"
    @.test.assertUrlMatch 'http://localhost:8000/pubtkt?back=https://', "redirected to pubtkt provider"
    @.test.assertSelectorHasText("p", 'Requested service URL "https://" is invalid', "Invalid return url error")

   @.thenOpen("http://localhost:8000/pubtkt")
   @.then ->
    @.capture("screenshots_pubtkt_invalid_return5.png")
    @.test.assertHttpStatus 200, "pubtkt without return url"
    @.test.assertUrlMatch 'http://localhost:8000/pubtkt', "No redirect"
    @.test.assertSelectorHasText("p", 'No return URL was defined on your request.', "Empty return url error")


   @.thenOpen("http://localhost:8000/pubtkt?back=asdf&unauth=1")
   @.then ->
    @.capture("screenshots_pubtkt_unauth.png")
    @.test.assertHttpStatus 200, "pubtkt with unauth=1"
    @.test.assertUrlMatch 'http://localhost:8000/pubtkt?back=asdf', "Was not redirected"
    @.test.assertSelectorHasText(".alert-danger", "Your don't have access to requested resource.", "No access error")

   @.thenOpen("http://localhost:8000/pubtkt?back=https://www.futurice.com")
   @.then ->
    @.test.assertUrlMatch 'https://www.futurice.com', "pubtkt redirected to proper destination"


   @.then ->
    @.echo("Clearing cookies and testing SSO providers again")
    phantom.clearCookies()
   @.thenOpen("http://localhost:8000/openid/")
   @.then ->    
    @.test.assertHttpStatus 200, "OpenID without cookies"
   @.thenOpen("http://localhost:8000/openid/test_valid")
   @.then ->    
    @.test.assertHttpStatus 200, "OpenID identifier without cookies"
   @.thenOpen("http://localhost:8000/openid/test_invalid_user")
   @.then ->    
    @.test.assertHttpStatus 200, "Invalid OpenID identifier without cookies"
   @.thenOpen("http://localhost:8000/openid/?openid.assoc_handle=%7BHMAC-SHA1%7D%7B5309f4f9%7D%7BcYLgyA%3D%3D%7D&openid.claimed_id=http%3A%2F%2Flocalhost:8000%2Fopenid%2Ftest_valid&openid.identity=http%3A%2F%2Flocalhost:8000%2Fopenid%2Ftest_valid&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.pape.preferred_auth_policies=http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor-physical+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fphishing-resistant&openid.realm=http%3A%2F%2Fopenid-consumer.appspot.com&openid.return_to=http%3A%2F%2Fopenid-consumer.appspot.com%2Ffinish%3Fsession_id%3D3758021%26janrain_nonce%3D2014-02-27T14%253A17%253A46ZKfCLSy&openid.sreg.optional=nickname%2Cfullname%2Cemail")
   @.then ->
    @.test.assertHttpStatus 200, "Valid OpenID request with cookies"


   @.thenOpen("http://localhost:8000/pubtkt?back=https://www.futurice.com")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=pubtkt&back=https://www.futurice.com', "Valid pubtkt request with no login redirected"
    @.test.assertHttpStatus 200

   # Special case: browser not defined
   @.then ->
    phantom.clearCookies()
   @.thenOpen("http://localhost:8000/pubtkt?back=https://www.futurice.com")
   @.then ->
    @.test.assertUrlMatch 'http://localhost:8000/first/password?_sso=pubtkt&back=https://www.futurice.com', "Valid pubtkt request with no browser"
    @.test.assertHttpStatus 200
 

casper.run ->
  @.test.done()
