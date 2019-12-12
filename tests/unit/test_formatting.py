import unittest
from nose.tools import raises, assert_equal, assert_true, assert_false

from parliament import analyze_policy_string


class TestFormatting(unittest.TestCase):
    """Test class for formatting"""

    def test_analyze_policy_string_not_json(self):
        policy = analyze_policy_string("not json")
        assert_false(len(policy.findings) == 0, "Policy is not valid json")

    def test_analyze_policy_string_opposites(self):
        # Policy contains Action and NotAction
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "NotAction": "s3:listallmybuckets",
        "Resource": "*"}}"""
        )
        assert_false(len(policy.findings) == 0, "Policy contains Action and NotAction")

    def test_analyze_policy_string_no_action(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Resource": "*"}}"""
        )
        assert_false(len(policy.findings) == 0, "Policy does not have an Action")

    def test_analyze_policy_string_no_statement(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17" }"""
        )
        assert_false(len(policy.findings) == 0, "Policy has no Statement")

    def test_analyze_policy_string_invalid_sid(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "Statement With Spaces And Special Chars!?",
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "Resource": "*"}}"""
        )
        assert_false(len(policy.findings) == 0, "Policy statement has invalid Sid")

    def test_analyze_policy_string_correct_simple(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listallmybuckets",
        "Resource": "*"}}"""
        )
        assert_equal(len(policy.findings), 0)

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
        "Resource": "*"}]}"""
        )
        assert_equal(len(policy.findings), 0)

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
        "Resource": "*"}]}"""
        )
        assert_false(
            len(policy.findings) == 0, "Policy with multiple statements has one bad"
        )

    def test_condition(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"DateGreaterThan" :{"aws:CurrentTime" : "2019-07-16T12:00:00Z"}} }}"""
        )
        assert_equal(len(policy.findings), 0)

    def test_condition_bad_key(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"DateGreaterThan" :{"bad" : "2019-07-16T12:00:00Z"}} }}"""
        )
        assert_false(len(policy.findings) == 0, "Policy has bad key in Condition")

    def test_condition_action_specific(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEquals": {"s3:prefix":["home/${aws:username}/*"]}} }}"""
        )
        assert_equal(len(policy.findings), 0)

        # The key s3:x-amz-storage-class is not allowed for ListBucket,
        # but is for other S3 actions
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEquals": {"s3:x-amz-storage-class":"bad"}} }}"""
        )
        assert_false(
            len(policy.findings) == 0,
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
        "Condition": {"StringEquals": {"s3:signatureage":"bad"}} }}"""
        )
        print(policy.findings)
        assert_false(len(policy.findings) == 0, 'Wrong type, "bad" should be a number')

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
        } }}"""
        )
        assert_equal(len(policy.findings), 0)

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
        } }}"""
        )
        assert_false(len(policy.findings) == 0, "First condition is bad")

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
        } }}"""
        )
        assert_false(len(policy.findings) == 0, "Second condition is bad")

    def test_condition_mismatch(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": ["ec2:*", "s3:*"],
        "Resource": "*",
        "Condition": {"StringNotEquals": {"iam:ResourceTag/status":"prod"}} }}"""
        )
        assert_false(len(policy.findings) == 0, "Condition mismatch")

    def test_condition_operator(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"StringEqualsIfExists": {"s3:prefix":["home/${aws:username}/*"]}} }}"""
        )
        print(policy.findings)
        assert_equal(len(policy.findings), 0)

        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"bad": {"s3:prefix":["home/${aws:username}/*"]}} }}"""
        )
        assert_false(len(policy.findings) == 0, "Unknown operator")

        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:listbucket",
        "Resource": "arn:aws:s3:::bucket-name",
        "Condition": {"NumericEquals": {"s3:prefix":["home/${aws:username}/*"]}} }}"""
        )
        assert_false(len(policy.findings) == 0, "Operator type mismatch")

    def test_condition_type_unqoted_bool(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "kms:CreateGrant",
        "Resource": "*",
        "Condition": {"Bool": {"kms:GrantIsForAWSResource": true}} }}"""
        )
        print(policy.findings)
        assert_equal(len(policy.findings), 0)
    
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
 }"""
        )
        print(policy.findings)
        assert_equal(len(policy.findings), 0)
    
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
 }"""
        )
        print(policy.findings)
        assert_equal(len(policy.findings), 0)