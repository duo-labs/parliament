import unittest
from nose.tools import raises, assert_equal, assert_true, assert_false

from parliament import analyze_policy_string


class TestFormatting(unittest.TestCase):
    """Test class for formatting"""

    def test_analyze_policy_string_not_json(self):
        policy = analyze_policy_string("not json")
        assert_equal(
            policy.finding_ids, set(["MALFORMED_JSON"]), "Policy is not valid json"
        )

    def test_analyze_policy_string_opposites(self):
        # Policy contains Action and NotAction
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "NotAction": "s3:listallmybuckets",
        "Resource": "*"}}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["MALFORMED"]),
            "Policy contains Action and NotAction",
        )

    def test_analyze_policy_string_no_action(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Resource": "*"}}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(["MALFORMED"]), "Policy does not have an Action"
        )

    def test_analyze_policy_string_no_statement(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17" }"""
        )
        assert_equal(policy.finding_ids, set(["MALFORMED"]), "Policy has no Statement")

    def test_analyze_policy_string_invalid_sid(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "Statement With Spaces And Special Chars!?",
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "Resource": "*"}}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(["INVALID_SID"]), "Policy statement has invalid Sid"
        )

    def test_analyze_policy_string_correct_simple(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "Resource": "*"}}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(),
        )

    def test_analyze_policy_string_correct_multiple_statements_and_actions(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "Resource": "*"},
        {
        "Effect": "Allow",
        "Action": "iam:listusers",
        "Resource": "*"}]}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(),
        )

    def test_analyze_policy_string_multiple_statements_one_bad(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "Resource": "*"},
        {
        "Effect": "Allow",
        "Action": ["iam:listusers", "iam:list"],
        "Resource": "*"}]}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["UNKNOWN_ACTION"]),
            "Policy with multiple statements has one bad",
        )

    def test_condition(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"DateGreaterThan" :{"aws:CurrentTime" : "2019-07-16T12:00:00Z"}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(policy.finding_ids, set())

    def test_condition_bad_key(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"DateGreaterThan" :{"bad" : "2019-07-16T12:00:00Z"}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["UNKNOWN_CONDITION_FOR_ACTION"]),
            "Policy has bad key in Condition",
        )

    def test_condition_action_specific(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEquals": {"s3:prefix":["home/${aws:username}/*"]}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(policy.finding_ids, set())

        # The key s3:x-amz-storage-class is not allowed for ListBucket,
        # but is for other S3 actions
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEquals": {"s3:x-amz-storage-class":"bad"}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["UNKNOWN_CONDITION_FOR_ACTION"]),
            "Policy uses key that cannot be used for the action",
        )

    def test_condition_action_specific_bad_type(self):
        # s3:signatureage requires a number
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEquals": {"s3:signatureage":"bad"}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["MISMATCHED_TYPE"]),
            'Wrong type, "bad" should be a number',
        )

    def test_condition_multiple(self):
        # Both good
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {
            "DateGreaterThan" :{"aws:CurrentTime" : "2019-07-16T12:00:00Z"},
            "StringEquals": {"s3:prefix":["home/${aws:username}/*"]}
        } }}""",
            ignore_private_auditors=True,
        )
        assert_equal(policy.finding_ids, set())

        # First bad
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {
            "DateGreaterThan" :{"aws:CurrentTime" : "bad"},
            "StringEquals": {"s3:prefix":["home/${aws:username}/*"]}
        } }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(["MISMATCHED_TYPE"]), "First condition is bad"
        )

        # Second bad
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {
            "DateGreaterThan" :{"aws:CurrentTime" : "2019-07-16T12:00:00Z"},
            "StringEquals": {"s3:x":["home/${aws:username}/*"]}
        } }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["UNKNOWN_CONDITION_FOR_ACTION"]),
            "Second condition is bad",
        )

    def test_condition_mismatch(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": ["ec2:*", "s3:*"],
        "Resource": "*",
        "Condition": {"StringNotEquals": {"iam:ResourceTag/status":"prod"}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["UNKNOWN_CONDITION_FOR_ACTION", "RESOURCE_STAR"]),
            "Condition mismatch",
        )

    def test_condition_operator(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEqualsIfExists": {"s3:prefix":["home/${aws:username}/*"]}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(policy.finding_ids, set())

        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"bad": {"s3:prefix":["home/${aws:username}/*"]}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids,
            set(["UNKNOWN_OPERATOR", "MISMATCHED_TYPE"]),
            "Unknown operator",
        )

        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"NumericEquals": {"s3:prefix":["home/${aws:username}/*"]}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(["MISMATCHED_TYPE"]), "Operator type mismatch"
        )

    def test_condition_type_unqoted_bool(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "kms:CreateGrant",
        "Resource": "*",
        "Condition": {"Bool": {"kms:GrantIsForAWSResource": true}} }}""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(["RESOURCE_STAR"]),
        )

    def test_condition_with_null(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
      {
        "Sid": "",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::examplebucket/taxdocuments/*",
        "Condition": { "Null": { "aws:MultiFactorAuthAge": true }}
      }
    ]
 }""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(),
        )

    def test_condition_with_MultiFactorAuthAge(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
      {
        "Sid": "",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": { "NumericGreaterThan": { "aws:MultiFactorAuthAge": "28800" }}
      }
    ]
 }""",
            ignore_private_auditors=True,
        )
        assert_equal(
            policy.finding_ids, set(),
        )

    def test_redshift_GetClusterCredentials(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
        {
            "Action": "redshift:GetClusterCredentials",
            "Effect": "Allow",
            "Resource": "arn:aws:redshift:us-west-2:123456789012:dbuser:the_cluster/the_user"
        }
    ]
 }""",
            ignore_private_auditors=True,
        )

        # This privilege has a required format of arn:*:redshift:*:*:dbuser:*/*
        assert_equal(
            policy.finding_ids, set(),
        )

    def test_lambda_AddLayerVersionPermission(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
        {
            "Sid": "TestPol",
            "Effect": "Allow",
            "Action": "lambda:AddLayerVersionPermission",
            "Resource": "arn:aws:lambda:*:123456789012:layer:sol-*:*"
        }
    ]
 }""",
            ignore_private_auditors=True,
        )

        # This privilege has a required format of arn:*:redshift:*:*:dbuser:*/*
        assert_equal(
            policy.finding_ids, set(),
        )

    def test_lambda_TerminateInstances(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
        {
            "Action": [
                "ec2:TerminateInstances"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Condition": {
                "ArnEquals": {
                    "ec2:InstanceProfile": "arn:aws:iam::123456789012:instance-profile/my_role"
                }
            }
        }
    ]
 }""",
            ignore_private_auditors=True,
        )

        assert_equal(
            policy.finding_ids, set(["RESOURCE_STAR"]),
        )

    def test_priv_that_requires_star_resource(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
        {
            "Action": [
                "guardduty:ListDetectors"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}""",
            ignore_private_auditors=True,
        )

        # guardduty:ListDetectors has no required resources, so it can have "*".
        # This should not create a RESOURCE_STAR finding

        assert_equal(
            policy.finding_ids, set(),
        )

    def test_condition_operator_values(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:TerminateInstances"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "ec2:InstanceProfile": "arn:aws:iam::123456789012:instance-profile/my_role"
                }
            }
        }
    ]
}""",
            ignore_private_auditors=True,
        )

        assert_equal(
            policy.finding_ids, set(["RESOURCE_STAR", "MISMATCHED_TYPE_BUT_USABLE"]),
        )
    
    def test_duplicate_sids(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "stmt",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Sid": "stmt",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }

    ]
}""",
            ignore_private_auditors=True,
        )

        assert_equal(
            policy.finding_ids, set(["DUPLICATE_SID"]),
        )

    def test_analyze_policy_string_MFA_formatting(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
            "Sid": "AllowManageOwnVirtualMFADevice",
            "Effect": "Allow",
            "Action": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice"
            ],
            "Resource": "arn:aws:iam::*:mfa/${aws:username}"
        }
        }"""
        )
        assert_equal(policy.finding_ids, set([]), "Policy is valid")
