import unittest
from nose.tools import raises, assert_equal

# import parliament
from parliament import analyze_policy_string


class TestCredentialsManagement(unittest.TestCase):
    """Test class for Credentials Management auditor"""

    def test_credentials_management(self):
        example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "redshift:getclustercredentials",
                "ecr:getauthorizationtoken"
              ],
              "Resource": "*"
            }
          ]
        }
        """
        policy = analyze_policy_string(example_policy_string)
        print(policy.policy_json)
        print(policy.findings)
        assert_equal(len(policy.findings), 2)
