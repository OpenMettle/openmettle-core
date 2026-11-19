"""Exercise the Keycloak sign-in journey and its input handling without Chrome or a provider."""
import json
from pathlib import Path
import unittest

from keycloak import (HARNESS_SECONDS, PROVIDER_SECONDS, REFUSALS, journey, parse_input,
                      provider_address, resolver_rules, run, site)
from qualify import Failure, Progress

APPLICATION = "https://app.relying.test:18443"
PROVIDER = "https://keycloak.provider.test:8443"
REALM_PATH = "/realms/openmettle-qualification"
PASSWORD = "synthetic-password-never-reported"
CODE = "omh1-0123-4567-89ab-cdef-fedc-ba98-7654-3210"
ACCOUNT = {"username": "synthetic-user", "password": PASSWORD, "invitation_code": None}
INPUT = {"authorities": ["-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"], **ACCOUNT}


class Page:
    """A scripted browser. Waits succeed unless their failure phrase is listed in `stuck`;
    `shown` is the application page text that a refusal lookup then finds."""

    def __init__(self, stuck=(), shown=None):
        self.stuck, self.shown = stuck, shown
        self.session = None
        self.steps = []

    def call(self, method, **params):
        self.steps.append(("call", method, params.get("url")))
        return {"targetId": "target", "sessionId": "session"}

    def evaluate(self, expression):
        self.steps.append(("evaluate", expression))
        if "innerText" in expression:
            return self.shown
        if "fetch('/session').then(r => r.status)" in expression:
            return 204
        return True

    def wait_for(self, expression, phase, seconds=12):
        self.steps.append(("wait", expression, seconds))
        if phase in self.stuck:
            raise Failure(phase)

    def click(self, element):
        self.steps.append(("click", element))

    def expressions(self):
        return [step[1] for step in self.steps if step[0] in ("evaluate", "wait")]


def phases(page, account=ACCOUNT):
    entered = []
    journey(page, APPLICATION, PROVIDER, REALM_PATH, account, entered.append)
    return entered


class JourneyTests(unittest.TestCase):
    def test_phases_run_in_order_and_the_form_is_awaited_before_the_credentials(self):
        page = Page()
        self.assertEqual(phases(page), [
            "browser target setup", "login page", "provider login form", "provider credentials",
            "callback and landing", "issued session check", "logout", "signed-out session check"])
        clicks = [step[1] for step in page.steps if step[0] == "click"]
        self.assertEqual(clicks, ["login", "kc-login", "logout"])
        form = next(step for step in page.steps if step[0] == "wait" and "kc-login" in step[1])
        self.assertIn(f'location.origin === "{PROVIDER}"', form[1])
        self.assertIn(f'location.pathname.startsWith("{REALM_PATH}/")', form[1])
        self.assertEqual(form[2], PROVIDER_SECONDS)
        typed = next(index for index, step in enumerate(page.steps)
                     if step[0] == "evaluate" and PASSWORD in step[1])
        self.assertLess(page.steps.index(form), typed)
        self.assertLess(typed, page.steps.index(("click", "kc-login")))
        # The password is typed once, into the provider form, and nowhere else.
        self.assertEqual(sum(PASSWORD in expression for expression in page.expressions()), 1)

    def test_an_invitation_code_is_entered_on_the_application_form_only_when_supplied(self):
        self.assertFalse(any("invitation" in expression for expression in Page().expressions()))
        page = Page()
        entered = phases(page, {**ACCOUNT, "invitation_code": CODE})
        self.assertEqual(entered[1:3], ["login page", "invitation code entry"])
        typed = next(index for index, step in enumerate(page.steps)
                     if step[0] == "evaluate" and CODE in step[1])
        self.assertIn("getElementById('invitation')", page.steps[typed][1])
        self.assertLess(typed, page.steps.index(("click", "login")))

    def test_a_missing_document_is_reported_by_its_fixed_phrase(self):
        for stuck in ("provider login form did not load", "document did not commit at /app"):
            with self.subTest(stuck=stuck), self.assertRaisesRegex(Failure, f"^{stuck}$"):
                phases(Page(stuck=(stuck,)))

    def test_an_application_refusal_is_reported_by_its_own_fixed_line(self):
        for line in REFUSALS:
            with self.subTest(line=line), self.assertRaises(Failure) as raised:
                phases(Page(stuck=("document did not commit at /app",), shown=line))
            self.assertEqual(str(raised.exception), f"application answered: {line}")

    def test_other_page_text_is_never_reported(self):
        with self.assertRaisesRegex(Failure, "^provider login form did not load$"):
            phases(Page(stuck=("provider login form did not load",), shown="sensitive page text"))

    def test_the_refusal_lines_match_the_handoff_source(self):
        source = (Path(__file__).resolve().parents[2] / "src/browser_auth/handoff.rs").read_text()
        for line in REFUSALS:
            self.assertIn(json.dumps(line + "\n"), source)


class InputTests(unittest.TestCase):
    def test_sites_are_canonical_https_and_use_the_browser_origin_form(self):
        self.assertEqual(site(APPLICATION, path_allowed=False),
                         (APPLICATION, "app.relying.test", 18443, ""))
        self.assertEqual(site(PROVIDER + REALM_PATH, path_allowed=True),
                         (PROVIDER, "keycloak.provider.test", 8443, REALM_PATH))
        self.assertEqual(site("https://app.relying.test", path_allowed=False)[0],
                         "https://app.relying.test")
        for url, path_allowed in [
            ("http://app.relying.test", False), ("https://app.relying.test/", False),
            ("https://app.relying.test/app", False), ("https://app.relying.test:443", False),
            ("https://APP.relying.test", False), ("https://app.relying.test:x", False),
            ("https://user@app.relying.test", False), ("https://app.relying.test?q", False),
            ("https://a,b.test/realms/r", True), ("https://a b.test/realms/r", True),
            ("https://keycloak.provider.test/realms/r/", True),
            ("https://keycloak.provider.test/realms/r#f", True),
            ("https://keycloak.provider.test/realms/'r", True),
        ]:
            with self.subTest(url=url), self.assertRaisesRegex(Failure, "^harness site invalid$"):
                site(url, path_allowed)

    def test_the_provider_resolves_to_exactly_one_ipv4_address(self):
        def answers(*addresses):
            return lambda host, port, family, kind: [(family, kind, 6, "", (a, port)) for a in addresses]
        self.assertEqual(provider_address("keycloak.provider.test", 8443, answers("172.17.0.2", "172.17.0.2")),
                         "172.17.0.2")
        for lookup in (answers(), answers("172.17.0.2", "172.17.0.3"), answers("not-an-address")):
            with self.assertRaisesRegex(Failure, "^provider address not resolved$"):
                provider_address("keycloak.provider.test", 8443, lookup)

        def unresolved(*_):
            raise OSError("sensitive resolver detail")
        with self.assertRaisesRegex(Failure, "^provider address not resolved$"):
            provider_address("keycloak.provider.test", 8443, unresolved)

    def test_chrome_resolves_the_two_sites_and_nothing_else(self):
        self.assertEqual(
            resolver_rules("app.relying.test", "keycloak.provider.test", "172.17.0.2"),
            "MAP app.relying.test 127.0.0.1, MAP keycloak.provider.test 172.17.0.2, MAP * ~NOTFOUND")

    def test_input_has_exactly_the_four_members(self):
        authorities, account = parse_input(json.dumps(INPUT).encode())
        self.assertEqual(authorities, [INPUT["authorities"][0].encode()])
        self.assertEqual(account["password"], PASSWORD)
        self.assertIsNone(account["invitation_code"])
        self.assertEqual(parse_input(json.dumps({**INPUT, "invitation_code": CODE}).encode())[1]
                         ["invitation_code"], CODE)
        without_password = {name: value for name, value in INPUT.items() if name != "password"}
        for value in [without_password, {**INPUT, "extra": 1}, {**INPUT, "password": ""},
                      {**INPUT, "authorities": []}, {**INPUT, "authorities": "pem"},
                      {**INPUT, "authorities": ["café"]}, {**INPUT, "username": 7},
                      {**INPUT, "invitation_code": ""}, [INPUT], "text", None]:
            with self.subTest(value=value), self.assertRaises(Failure) as raised:
                parse_input(json.dumps(value).encode())
            # The refusal names no member and repeats no value.
            self.assertEqual(str(raised.exception), "harness input invalid")
        with self.assertRaisesRegex(Failure, "^harness input invalid$"):
            parse_input(b"{" + PASSWORD.encode())

    def test_refused_arguments_end_before_any_browser_work(self):
        progress = Progress()
        raw = json.dumps(INPUT).encode()
        for application, issuer in [
            (APPLICATION, PROVIDER),  # an issuer without a realm path
            (APPLICATION + "/app", PROVIDER + REALM_PATH),
            (APPLICATION, "https://app.relying.test:8443" + REALM_PATH),  # one host for both sites
        ]:
            with self.subTest(issuer=issuer), self.assertRaisesRegex(Failure, "^harness site invalid$"):
                run(application, issuer, None, progress.enter, raw)
            self.assertEqual(progress.phase, "harness input")

    def test_the_alarm_covers_both_provider_waits(self):
        self.assertGreater(HARNESS_SECONDS, 2 * PROVIDER_SECONDS + 3 * 12)


if __name__ == "__main__":
    unittest.main()
