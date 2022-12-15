import parliament

from parliament import UnknownPrefixException, UnknownActionException
from parliament.statement import expand_action


class TestActionExpansion:
    """Test class for expand_action function"""

    def test_expand_action_no_expansion(self):
        expanded_actions = expand_action("s3:listallmybuckets")
        assert len(expanded_actions) == len(
            [{"service": "s3", "action": "ListAllMyBuckets"}]
        )

    def test_expand_action_with_expansion(self):
        expanded_actions = expand_action("s3:listallmybucke*")
        assert len(expanded_actions) == len(
            [{"service": "s3", "action": "ListAllMyBuckets"}]
        )

    def test_expand_action_with_casing(self):
        expanded_actions = expand_action("iAm:li*sTuS*rs")
        assert len(expanded_actions) == len([{"service": "iam", "action": "ListUsers"}])

    def test_expand_action_with_expansion_for_prefix_used_multiple_times(self):
        expanded_actions = expand_action("ses:Describe*")
        assert len(expanded_actions) == len(
            [
                {"service": "ses", "action": "DescribeActiveReceiptRuleSet"},
                {"service": "ses", "action": "DescribeConfigurationSet"},
                {"service": "ses", "action": "DescribeReceiptRule"},
                {"service": "ses", "action": "DescribeReceiptRuleSet"},
            ]
        )

    def test_expand_action_with_permission_only_action(self):
        # There are 17 privileges list as "logs.CreateLogDelivery [permission only]"
        expanded_actions = expand_action("logs:GetLogDelivery")
        assert len(expanded_actions) == len(
            [{"service": "logs", "action": "GetLogDelivery"}]
        )

    def test_exception_malformed(self):
        try:
            expand_action("malformed")
            assert False
        except ValueError as e:
            assert True

    def test_exception_bad_service(self):
        try:
            expand_action("333:listallmybuckets")
            assert False, "333 is not a valid prefix"
        except UnknownPrefixException as e:
            assert True

    def test_exception_bad_action(self):
        try:
            expand_action("s3:zzz")
            assert False, "s3:zzz is not a valid action"
        except UnknownActionException as e:
            assert True

    def test_exception_bad_expansion(self):
        try:
            expand_action("s3:zzz*")
            assert False, "No expansion is possible from s3:zzz*"
        except UnknownActionException as e:
            assert True

    def test_expand_all(self):
        assert len(expand_action("*")) > 5000
        assert len(expand_action("*:*")) > 5000

    def test_expand_iq(self):
        expand_action("iq:*")
        assert True

        try:
            expand_action("iq:dostuff")
            assert False, "iq:dostuff is invalid"
        except UnknownActionException as e:
            assert True
