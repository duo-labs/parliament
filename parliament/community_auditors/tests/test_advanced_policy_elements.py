import unittest

from nose.tools import assert_equal

from parliament import analyze_policy_string

S3_STAR_FINDINGS = {"PERMISSIONS_MANAGEMENT_ACTIONS", "RESOURCE_MISMATCH"}


class TestAdvancedPolicyElements(unittest.TestCase):
    def test_notresource_allow(self):
        # NotResource is OK with Effect: Deny. This denies access to
        # all S3 buckets except Payroll buckets. This example is taken from
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html
        policystr = """{
          "Version": "2012-10-17",
          "Statement": {
            "Effect": "Deny",
            "Action": "s3:*",
            "NotResource": [
              "arn:aws:s3:::HRBucket/Payroll",
              "arn:aws:s3:::HRBucket/Payroll/*"
            ]
          }
        }"""

        policy = analyze_policy_string(policystr, include_community_auditors=True)
        assert_equal(policy.finding_ids, set())

        # According to AWS documentation, "This statement is very dangerous,
        # because it allows all actions in AWS on all resources except the
        # HRBucket S3 bucket." See:
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html#notresource-element-combinations
        policystr = """{
          "Version": "2012-10-17",
          "Statement": {
            "Effect": "Allow",
            "Action": "s3:*",
            "NotResource": [
              "arn:aws:s3:::HRBucket/Payroll",
              "arn:aws:s3:::HRBucket/Payroll/*"
            ]
          }
        }"""

        policy = analyze_policy_string(policystr, include_community_auditors=True)

        assert_equal(policy.finding_ids, S3_STAR_FINDINGS | {"NOTRESOURCE_WITH_ALLOW"})

    def test_notprincipal_allow(self):
        # NotPrincipal is OK with Effect: Deny. This explcitly omits these
        # users from the list of Principals denied access to this resource
        # This example is taken from https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html#specifying-notprincipal
        policystr = """{
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Deny",
            "NotPrincipal": {"AWS": [
              "arn:aws:iam::444455556666:user/Bob",
              "arn:aws:iam::444455556666:root"
            ]},
            "Action": "s3:*",
            "Resource": [
              "arn:aws:s3:::BUCKETNAME",
              "arn:aws:s3:::BUCKETNAME/*"
            ]
          }]
        }"""

        policy = analyze_policy_string(policystr, include_community_auditors=True)

        assert_equal(policy.finding_ids, set())

        # This implicitly allows everyone _except_ Bob to access BUCKETNAME!
        policystr = """{
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "NotPrincipal": {"AWS": [
              "arn:aws:iam::444455556666:user/Bob",
            ]},
            "Action": "s3:*",
            "Resource": [
              "arn:aws:s3:::BUCKETNAME",
              "arn:aws:s3:::BUCKETNAME/*"
            ]
          }]
        }"""

        policy = analyze_policy_string(policystr, include_community_auditors=True)

        assert_equal(policy.finding_ids, S3_STAR_FINDINGS | {"NOTPRINCIPAL_WITH_ALLOW"})
