import unittest

from nose.tools import assert_equal

# import parliament
from parliament import analyze_policy_string


class TestPermissionsManagement(unittest.TestCase):
    """Test class for Permissions Management auditor"""

    def test_permissions_management(self):
        example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "lambda:addpermission",
                "s3:putbucketacl",
                "ram:CreateResourceShare"
              ],
              "Resource": "*"
            }
          ]
        }
        """
        policy = analyze_policy_string(
            example_policy_string, include_community_auditors=True
        )

        assert_equal(
            policy.finding_ids,
            set(
                [
                    "PERMISSIONS_MANAGEMENT_ACTIONS",
                    "RESOURCE_POLICY_PRIVILEGE_ESCALATION",
                    "RESOURCE_STAR",
                ]
            ),
        )
