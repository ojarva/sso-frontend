CasperJS
========

These tests are for CasperJS. Before running, set ```FAKE_TESTING=True```. This enables static usernames and SMS codes. Never set this value on production environment. Run with

```
python manage.py testserver login_frontend/fixtures/casper.json
casperjs test casper_smoketests
```

After each run, restart "testserver", as casper tests do not reset the database.
