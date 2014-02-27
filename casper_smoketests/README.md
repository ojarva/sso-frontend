CasperJS
========

These tests are for CasperJS. However, these are designed to run one-by-one. Running ```casperjs test casper_smoketests``` fails, as it shares
cookies between all tests.

Run these tests with ```python manage.py testserver login_frontend/fixtures/casper.json```. Set ```FAKE_TESTING=True``` (static usernames and OTP code).
