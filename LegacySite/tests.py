from django.test import TestCase, Client
from LegacySite.models import Card
from io import StringIO

# Create your tests here.

class MyTest(TestCase):
    # Django's test run with an empty database. We can populate it with
    # data by using a fixture. You can create the fixture by running:
    #    mkdir LegacySite/fixtures
    #    python manage.py dumpdata LegacySite > LegacySite/fixtures/testdata.json
    # You can read more about fixtures here:
    #    https://docs.djangoproject.com/en/4.0/topics/testing/tools/#fixture-loading
    fixtures = ["testdata.json"]

    def setUp(self):
        self.client = Client()

    # Assuming that your database had at least one Card in it, this
    # test should pass.
    def test_get_card(self):
        allcards = Card.objects.all()
        self.assertNotEqual(len(allcards), 0)

    def test_xss(self):
        response = self.client.get('/gift.html?director=<script>alert("One attack, that exploits a XSS (cross-site scripting) vulnerability")</script>')
        # will fail if malicious characters aren't escaped properly --> resulting in XSS
        self.assertContains(response, '&lt;script&gt;alert(&quot;One attack, that exploits a XSS (cross-site scripting) vulnerability&quot;)&lt;/script&gt;')

    def test_csrf(self):
        self.csrfclient = Client(enforce_csrf_checks = True)
        response = self.csrfclient.get('/gift.html')
        # will fail if csrf_protect is not used
        self.assertContains(response, 'csrfmiddlewaretoken')
        response = self.csrfclient.post('/gift.html', {'username':'attacker', 'amount':1337})
        # will fail if csrf goes through
        self.assertEqual(response.status_code, 403)

    def test_sql_injection(self):
        # self.client.post('/register.html', {'uname':'attacker', 'pword':'nefarious', 'pword2':'nefarious'})
        admin_password_hash = '000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3'
        self.client.login(username='attacker', password='nefarious')
        payload = """{"merchant_id": "NYU Apparel Card", "customer_id": "asdf", "total_value": "23", "records": [{"record_type": "amount_change", "amount_added": 2000, "signature": "' AND 1=0 UNION SELECT password FROM LegacySite_user WHERE username = 'admin' -- "}]}"""
        sql_gftcrd = StringIO(payload)
        response = self.client.post('/use.html', {'card_data':sql_gftcrd, 'card_supplied':True})
        # will fail if correct admin_password_hash is leaked through sql injection
        self.assertNotContains(response, admin_password_hash)

    #incomplete
    def test_command_injection(self):
        self.client.login(username='attacker', password='nefarious')
        gftcrd = StringIO("CORRUPTED")
        payload = "; echo HELLO YOU ARE BEING INJECTED; whoami; ifconfig;"
        payload = 'attacker'
        response = self.client.post('/use.html', {'card_data':gftcrd, 'card_supplied':True, 'card_fname':payload})
