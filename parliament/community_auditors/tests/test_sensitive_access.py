import unittest

from nose.tools import assert_equal

from parliament import analyze_policy_string


class TestSensitiveAccess(unittest.TestCase):
    """Test class for Sensitive access auditor"""

    def setUp(self) -> None:
        self.config = {
            "SENSITIVE_ACCESS": {
                "resources": [{"s3:GetObject": ["arn:aws:s3:::secret*"]}]
            }
        }

    def test_sensitive_access(self) -> None:
        example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject"
              ],
              "Resource": "arn:aws:s3:::secretbucket/*"
            },
            {
              "Effect": "Allow",
              "Action": [
                "s3:PutObject"
              ],
              "Resource": "arn:aws:s3:::otherbucket/*"
            }
          ]
        }
        """
        policy = analyze_policy_string(
            example_policy_string, include_community_auditors=True, config=self.config
        )
        assert_equal(policy.finding_ids, set(["SENSITIVE_ACCESS"]))
