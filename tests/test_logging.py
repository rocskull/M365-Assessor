import json
import logging

from m365_assessor.logging import JsonFormatter, redact


def test_redacts_nested_credentials() -> None:
    value = redact({"client_secret": "bad", "nested": {"access_token": "also-bad"}})
    assert value == {"client_secret": "[REDACTED]", "nested": {"access_token": "[REDACTED]"}}


def test_redacts_bearer_header() -> None:
    assert redact("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer [REDACTED]"


def test_json_formatter() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello", (), None)
    record.context = {"password": "secret"}
    output = json.loads(JsonFormatter().format(record))
    assert output["message"] == "hello"
    assert output["context"]["password"] == "[REDACTED]"
