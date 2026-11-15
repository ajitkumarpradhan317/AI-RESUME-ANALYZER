import os
import unittest
from types import SimpleNamespace
from unittest import mock

from app_loader import load_app


class GetConfigTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_env_var_wins_over_secrets(self):
        self.ns["st"].secrets = {"X_SETTING": "from-secrets"}
        with mock.patch.dict(os.environ, {"X_SETTING": " from-env "}):
            self.assertEqual(self.ns["get_config"]("X_SETTING"), "from-env")

    def test_falls_back_to_secrets_then_default(self):
        self.ns["st"].secrets = {"X_SETTING": "from-secrets"}
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("X_SETTING", None)
            self.assertEqual(self.ns["get_config"]("X_SETTING"), "from-secrets")
            self.assertEqual(self.ns["get_config"]("NOPE_X", "dflt"), "dflt")

    def test_missing_secrets_file_does_not_crash(self):
        class Broken:
            def get(self, *a):
                raise FileNotFoundError
        self.ns["st"].secrets = Broken()
        os.environ.pop("NOPE_Y", None)
        self.assertEqual(self.ns["get_config"]("NOPE_Y", "d"), "d")


class BrevoEmailTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()
        self.cfg = {"BREVO_API_KEY": "key123", "BREVO_SENDER_EMAIL": "from@example.com"}
        self.ns["get_config"] = lambda name, default="": self.cfg.get(name, default)

    def send(self, post, name="Aarav", user="aarav.s"):
        self.ns["requests"] = SimpleNamespace(post=post)
        return self.ns["send_reset_email_brevo"]("to@example.com", name, user, "482913")

    def test_not_configured_makes_no_request(self):
        self.cfg.clear()
        post = mock.Mock()
        self.assertEqual(self.send(post), (False, "BREVO_NOT_CONFIGURED"))
        post.assert_not_called()

    def test_success_payload(self):
        post = mock.Mock(return_value=SimpleNamespace(status_code=201))
        ok, _ = self.send(post)
        self.assertTrue(ok)
        kwargs = post.call_args.kwargs
        self.assertEqual(post.call_args.args[0], "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(kwargs["headers"]["api-key"], "key123")
        self.assertEqual(kwargs["json"]["to"][0]["email"], "to@example.com")
        self.assertEqual(kwargs["json"]["sender"]["email"], "from@example.com")
        self.assertIn("482913", kwargs["json"]["htmlContent"])

    def test_user_data_is_html_escaped(self):
        post = mock.Mock(return_value=SimpleNamespace(status_code=201))
        self.send(post, name="<script>alert(1)</script>", user="<b>x</b>")
        body = post.call_args.kwargs["json"]["htmlContent"]
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_api_error_does_not_leak_response_body(self):
        post = mock.Mock(return_value=SimpleNamespace(status_code=401, text="secret-details"))
        ok, status = self.send(post)
        self.assertFalse(ok)
        self.assertIn("401", status)
        self.assertNotIn("secret-details", status)

    def test_network_error_is_handled(self):
        ok, status = self.send(mock.Mock(side_effect=ConnectionError("down")))
        self.assertFalse(ok)
        self.assertIn("Network Error", status)


if __name__ == "__main__":
    unittest.main()
