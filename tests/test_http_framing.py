from email.message import Message
from io import BytesIO

import pytest

from webapp.server import Handler, RequestError


@pytest.mark.parametrize("lengths", [("2", "3"), ("2", "2"), ("+2",), (" 2",), ("٢",)])
def test_ambiguous_or_non_ascii_content_length_is_rejected_before_reading(lengths):
    handler = Handler.__new__(Handler)
    handler.headers = Message()
    for length in lengths:
        handler.headers["Content-Length"] = length
    handler.rfile = BytesIO(b"{}")
    with pytest.raises(RequestError) as caught:
        handler._read_json()
    assert caught.value.code == 400
    assert handler.rfile.tell() == 0


def test_a_single_valid_length_still_parses():
    handler = Handler.__new__(Handler)
    handler.headers = Message()
    handler.headers["Content-Length"] = "2"
    handler.rfile = BytesIO(b"{}")
    assert handler._read_json() == {}
