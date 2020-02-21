import unittest
from nose.tools import raises, assert_equal, assert_not_equal, assert_true, assert_false

from parliament import analyze_policy_string


class TestGetResourcesForPrivilege(unittest.TestCase):
    """Test class for get_resources_for_privilege"""

    def test_policy_simple(self):
        policy = analyze_policy_string(
            """{
      "Version":"2012-10-17",
      "Statement":[
        {
          "Effect":"Allow",
          "Action":["s3:GetObject"],
          "Resource":["arn:aws:s3:::examplebucket/*"]
        }
      ]
    }"""
        )

        assert_equal(
            set(policy.statements[0].get_resources_for_privilege("s3", "GetObject")),
            set(["arn:aws:s3:::examplebucket/*"]),
            "s3:GetObject matches the object resource",
        )

        assert_equal(
            set(policy.statements[0].get_resources_for_privilege("s3", "PutObject")),
            set([]),
            "s3:PutObject not in policy",
        )

    def test_policy_multiple_resources(self):
        policy = analyze_policy_string(
            """{
          "Version":"2012-10-17",
          "Statement":[
            {
              "Effect":"Allow",
              "Action": "s3:*",
              "Resource":["arn:aws:s3:::examplebucket", "arn:aws:s3:::examplebucket/*"]
            }
          ]
        }"""
        )

        assert_equal(
            set(policy.statements[0].get_resources_for_privilege("s3", "GetObject")),
            set(["arn:aws:s3:::examplebucket/*"]),
            "s3:GetObject matches the object resource",
        )

        # s3:PutBucketPolicy will match on both because a bucket resource type is defined as:
        # "arn:*:s3:::*" so it doesn't care whether or not there is a slash
        # assert_equal(set(policy.statements[0].get_resources_for_privilege("s3", "PutBucketPolicy")), set(["arn:aws:s3:::examplebucket"]), "s3:PutBucketPolicy matches the bucket resource")

        assert_equal(
            set(
                policy.statements[0].get_resources_for_privilege(
                    "s3", "ListAllMyBuckets"
                )
            ),
            set([]),
            "s3:ListAllMyBuckets matches none of the resources",
        )
