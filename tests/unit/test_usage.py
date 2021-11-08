import unittest
from nose.tools import raises, assert_equal, assert_true, assert_false
import json
import parliament


class TestUsage(unittest.TestCase):
    """Test basic usage of the library"""

    def test_using_library(self):
        # This is a common use of the library, so just follow the path to ensure no exceptions are thrown.
        policy_doc = """
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListAllMyBuckets",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": { "aws:PrincipalTag/project": "web" }
                    }
                }
            ],
            "Version": "2012-10-17"
        }"""
        policy_doc = json.loads(policy_doc)
        policy = parliament.policy.Policy(policy_doc)
        policy.analyze()