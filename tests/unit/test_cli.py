import unittest
from nose.tools import (
    assert_true,
    assert_false,
)

from parliament.cli import is_finding_filtered
from parliament.finding import Finding


class TaggedFinding(Finding):
    def __init__(self, tags, severity="CRITICAL"):
        self.tags = tags
        self.severity = severity


class TestCLI(unittest.TestCase):
    """ Test class for parliament CLI. """

    def test_is_finding_filtered(self):
        exclude_tags = {}

        # If we don't exclude any tags, findings shouldn't be filtered
        assert_false(
            is_finding_filtered(
                finding=TaggedFinding(tags={"C"}), exclude_tags=exclude_tags
            )
        )

        # Allow untagged findings
        assert_false(
            is_finding_filtered(
                TaggedFinding(tags=set()),
                minimum_severity="INFO",
                exclude_tags=exclude_tags,
            )
        )
        # ... unless the untagged finding doesn't meet the severity threshold
        assert_true(
            is_finding_filtered(
                TaggedFinding(tags=set(), severity="INFO"),
                minimum_severity="LOW",
                exclude_tags=exclude_tags,
            )
        )

    def test_exclude_tag(self):
        exclude_tags = {"A", "B", "D"}

        assert_true(
            is_finding_filtered(
                TaggedFinding(tags={"A", "D"}), exclude_tags=exclude_tags
            )
        )
        assert_false(
            is_finding_filtered(TaggedFinding(tags={"C"}), exclude_tags=exclude_tags)
        )

        # Allow untagged findings
        assert_false(
            is_finding_filtered(TaggedFinding(tags=set()), exclude_tags=exclude_tags)
        )

        # Filter by severity even if tags match
        assert_true(
            is_finding_filtered(
                TaggedFinding(tags={"C"}, severity="INFO"),
                minimum_severity="LOW",
                exclude_tags=exclude_tags,
            )
        )
