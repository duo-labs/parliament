import unittest
from nose.tools import assert_not_equal, assert_equal

from parliament import analyze_policy_string

class TestResources(unittest.TestCase):

    def test_no_resource_mismatch(self):
        """ec2 instance is a valid resource type for RunInstances action"""
        policy = analyze_policy_string(
            """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ec2:RunInstances",
            "Resource":
            [
                "arn:aws:ec2:*:123456789012:instance/*"
            ]
        }
    ]
}
            """
        )

        assert_equal(len(policy.findings), 0)
        assert_not_equal(policy.finding_ids, {"RESOURCE_MISMATCH"})


    def test_resource_mismatch(self):
        policy = analyze_policy_string(
            """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ec2:RunInstances",
            "Resource":
            [
                "arn:aws:ec2:*:123456789012:fake_resource_type/*"
            ]
        }
    ]
}
""")

        assert_equal(policy.finding_ids, {"RESOURCE_MISMATCH"})


    def test_one_unrecognized_resource_no_resource_mismatch(self):
        policy = analyze_policy_string(
            """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ec2:RunInstances",
            "Resource":
            [
                "arn:aws:ec2:*:123456789012:instance/*",
                "arn:aws:ec2:*:123456789012:fake_instance/*"
            ]
        }
    ]
}
""")
        assert_equal(len(policy.findings), 0)

    def test_multiple_resource_mismatches(self):
        policy = analyze_policy_string(
            """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ec2:RunInstances",
            "Resource":
            [
                "arn:aws:ec2:*:123456789012:fake_instance/*",
                "arn:aws:ec2:*:123456789012:fake_instance_2/*"
            ]
        }
    ]
}
""")
        assert_equal(policy.finding_ids, {"RESOURCE_MISMATCH"})
        assert_equal(len(policy.findings), 1)
