import unittest
from nose.tools import raises, assert_equal, assert_true, assert_false
from parliament import analyze_policy_string


class TestCommunityAuditors(unittest.TestCase):
    """Test class for importing/enabling/disabling community auditors properly"""

    def test_analyze_policy_string_enable_community(self):
        """Enable community auditors with the policy string."""
        example_policy_with_wildcards = """{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "ecr:*",
                "s3:*"
              ],
              "Resource": "*"
            }
          ]
        }
        """
        policy = analyze_policy_string(
            example_policy_with_wildcards, include_community_auditors=True
        )
        """
        The resulting findings will look like this:
        MEDIUM - Credentials exposure - Policy grants access to API calls that can return credentials to the user -  - {'actions': ['ecr:getauthorizationtoken'], 'filepath': 'wildcards.json'}
        MEDIUM - Permissions management actions - Allows the principal to modify IAM, RAM, identity-based policies, or resource based policies. -  - {'actions': ['ecr:setrepositorypolicy', 's3:bypassgovernanceretention', 's3:deleteaccesspointpolicy', 's3:deletebucketpolicy', 's3:objectowneroverridetobucketowner', 's3:putaccesspointpolicy', 's3:putaccountpublicaccessblock', 's3:putbucketacl', 's3:putbucketpolicy', 's3:putbucketpublicaccessblock', 's3:putobjectacl', 's3:putobjectversionacl'], 'filepath': 'wildcards.json'}
        
        We are just not including the full results here because the Permissions management actions might expand as AWS expands their API. We don't want to have to update the unit tests every time that happens.
        """
        assert_equal(
            policy.finding_ids,
            set(
                [
                    "RESOURCE_STAR",
                    "CREDENTIALS_EXPOSURE",
                    "PERMISSIONS_MANAGEMENT_ACTIONS",
                ]
            ),
        )

    def test_analyze_policy_string_disable_community(self):
        """Disable community auditors with the policy string."""
        example_policy_with_wildcards = """{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "ecr:*",
                "s3:*"
              ],
              "Resource": "*"
            }
          ]
        }
        """
        policy = analyze_policy_string(
            example_policy_with_wildcards, include_community_auditors=False
        )

        assert_equal(policy.finding_ids, set(["RESOURCE_STAR"]))
