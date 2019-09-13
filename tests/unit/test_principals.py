import unittest
from nose.tools import raises, assert_equal, assert_true, assert_false

from parliament.policy import analyze_policy_string


class TestPrincipals(unittest.TestCase):
    """Test class for principals"""

    def test_policy_with_principal(self):
        # S3 bucket policy
        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"AddPerm",
      "Effect":"Allow",
      "Principal": "*",
      "Action":["s3:GetObject"],
      "Resource":["arn:aws:s3:::examplebucket/*"]
    }
  ]
}"""
        )
        assert_true(len(policy.findings) == 0, "Basic S3 bucket policy")

        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal": {"AWS": ["arn:aws:iam::000000000000:root","arn:aws:iam::111111111111:root"]},
      "Action":["s3:GetObject"],
      "Resource":["arn:aws:s3:::examplebucket/*"]
    }
  ]
}"""
        )
        assert_true(
            len(policy.findings) == 0,
            "S3 bucket policy with two accounts granted access via account ARN",
        )

        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal":{"AWS":"000000000000"},
      "Action":["s3:GetObject"],
      "Resource":["arn:aws:s3:::examplebucket/*"]
    }
  ]
}"""
        )
        assert_true(
            len(policy.findings) == 0,
            "S3 bucket policy with one account granted access via ID",
        )

        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal": { "AWS": "arn:aws:iam::000000000000:user/alice" },
      "Action":["s3:GetObject"],
      "Resource":["arn:aws:s3:::examplebucket/*"]
    }
  ]
}"""
        )
        assert_true(len(policy.findings) == 0, "S3 bucket policy with ARN of user")

        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal": { "Federated": "cognito-identity.amazonaws.com" },
      "Action":["s3:GetObject"],
      "Resource":["arn:aws:s3:::examplebucket/*"]
    }
  ]
}"""
        )
        assert_true(len(policy.findings) == 0, "Federated access")

    def test_bad_principals(self):
        # Good principal
        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"AddPerm",
      "Effect":"Allow",
      "Principal": "*",
      "Action":["s3:GetObject"],
      "Resource":["arn:aws:s3:::examplebucket/*"]
    }
  ]
}"""
        )
        assert_true(len(policy.findings) == 0, "Basic S3 bucket policy")
