CasperJS
========

These tests are for CasperJS. Before running, set ```FAKE_TESTING=True```. This enables static usernames and SMS codes. Never set this value on production environment. Run with

```
python manage.py testserver login_frontend/fixtures/casper.json
casperjs test casper_smoketests
```

After each run, restart "testserver", as casper tests do not reset the database.
Running same tests multiple times without reloading database fixtures causes problems,
as the tests does not clean up the state, including strong authentication configuration.

Additionally, when running multiple tests without database reset, the order
of the tests is important.
