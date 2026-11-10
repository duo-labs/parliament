import pytest

from parliament.cli import main


class TestCli:
    """Test class for CLI argument handling"""

    def test_minimal_and_json_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            main(
                [
                    "parliament",
                    "--minimal",
                    "--json",
                    "--string",
                    '{"Version": "2012-10-17", "Statement": []}',
                ]
            )
        assert exc_info.value.code == 2
