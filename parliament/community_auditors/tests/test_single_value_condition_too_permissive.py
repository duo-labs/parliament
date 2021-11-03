import unittest

from nose.tools import assert_equal

from parliament import analyze_policy_string


class TestSensitiveAccess(unittest.TestCase):
    """Test class for single value condition too permissive auditor"""
    example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject"
              ],
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "ForAllValues:StringEquals": {
                      "aws:ResourceTag/Tag": [
                          "Value"
                      ]

                  }
              }
            }
          ]
        }
    """
    policy = analyze_policy_string(
        example_policy_string, include_community_auditors=True
    )
    assert_equal(policy.finding_ids, set(["SINGLE_VALUE_CONDITION_TOO_PERMISSIVE"]))
