import unittest

from nose.tools import assert_equal

# import parliament
from parliament import analyze_policy_string


class TestPrivilegeEscalation(unittest.TestCase):
    """Test class for Privilege Escalation auditor"""

    def test_privilege_escalation(self):
        example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "glue:updatedevendpoint",
                "lambda:updatefunctioncode"
              ],
              "Resource": "*"
            }
          ]
        }
        """
        policy = analyze_policy_string(
            example_policy_string, include_community_auditors=True
        )
        assert_equal(policy.finding_ids, set(["PRIVILEGE_ESCALATION", "RESOURCE_STAR"]))
