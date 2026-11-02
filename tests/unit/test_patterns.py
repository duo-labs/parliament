import json

from parliament import analyze_policy_string, enhance_finding


class TestPatterns:
    """Test class for bad patterns"""

    def test_bad_mfa_condition(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent":"false"}}
        }}""",
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set(
            ["BAD_PATTERN_FOR_MFA"]
        ), "Policy contains bad MFA check"

    def test_resource_policy_privilege_escalation(self):
        # This policy is actually granting essentially s3:* due to the ability to put a policy on a bucket
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutBucketPolicy"],
        "Resource": "*"
        }}""",
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set(
            ["RESOURCE_POLICY_PRIVILEGE_ESCALATION", "RESOURCE_STAR"]
        ), "Resource policy privilege escalation"

        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [
        {
    "Action": [
        "s3:ListBucket",
        "s3:Put*",
        "s3:Get*",
        "s3:*MultipartUpload*"
    ],
    "Resource": [
        "*"
    ],
    "Effect": "Allow"
},
{
    "Action": [
        "s3:*Policy*",
        "sns:*Permission*",
        "sns:*Delete*",
        "s3:*Delete*",
        "sns:*Remove*"
    ],
    "Resource": [
        "*"
    ],
    "Effect": "Deny"
}
        ]}""",
            ignore_private_auditors=True,
        )

        assert policy.finding_ids == set(
            ["RESOURCE_POLICY_PRIVILEGE_ESCALATION", "RESOURCE_STAR"]
        ), "Resource policy privilege escalation across two statement"

    def test_resource_effectively_star(self):
        policy = analyze_policy_string(
            """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudtrailReadTrail",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:GetEventSelectors",
        "cloudtrail:PutEventSelectors"
      ],
      "Resource": [
        "arn:*:cloudtrail:*:*:trail/*"
      ]
    }
  ]
}"""
        )

        assert policy.finding_ids == set(
            ["RESOURCE_EFFECTIVELY_STAR"]
        ), "Resource policy spans all Cloudtrails even without an asterisk."

        policy = analyze_policy_string(
            """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "CloudtrailReadTrail",
          "Effect": "Allow",
          "Action": [
            "cloudtrail:GetEventSelectors",
            "cloudtrail:PutEventSelectors"
          ],
          "Resource": [
            "arn:aws:cloudtrail:us-east-1:000000000000:trail/*"
          ]
        }
      ]
    }"""
        )

        assert (
            policy.finding_ids == set()
        ), "Resource policy is scoped by AWS partition, account and region and is therefore not 'STAR'."

    def test_resource_policy_privilege_escalation_with_deny(self):
        # This test ensures if we have an allow on a specific resource, but a Deny on *,
        # that it is denied.
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Action": "s3:PutBucketPolicy",
        "Resource": "arn:aws:s3:::examplebucket"
        },
        {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
        }
        ]}""",
            ignore_private_auditors=True,
        )
        assert (
            policy.finding_ids == set()
        ), "Resource policy privilege escalation does not exist because all our denied"

    def test_resource_policy_privilege_escalation_at_bucket_level(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutBucketPolicy"],
        "Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"]
        }}""",
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set(
            ["RESOURCE_POLICY_PRIVILEGE_ESCALATION"]
        ), "Resource policy privilege escalation"

        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:*Bucket*", "s3:*Object*"],
        "Resource": ["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket1/*"]
        },
        {
        "Effect": "Allow",
        "Action": ["s3:*Object"],
        "Resource": ["arn:aws:s3:::bucket2/*"]
        }]}""",
            ignore_private_auditors=True,
        )
        # There is one finding for "No resources match for s3:ListAllMyBuckets which requires a resource format of *"
        assert policy.finding_ids == set(
            ["RESOURCE_MISMATCH"]
        ), "Buckets do not match so no escalation possible"


# # # The following test for detections of various bad patterns, but unfortunately
# # # these detections were never implemented.

# #     def test_bad_tagging(self):
# #         # This was the original policy used by AmazonSageMakerFullAccess
# #         policy = analyze_policy_string(
# #             """{
# #     "Version": "2012-10-17",
# #     "Statement": [
# #         {
# #     "Action": [
# #         "secretsmanager:CreateSecret",
# #         "secretsmanager:DescribeSecret",
# #         "secretsmanager:ListSecrets",
# #         "secretsmanager:TagResource"
# #     ],
# #     "Resource": "*",
# #     "Effect": "Allow"
# # },
# # {
# #     "Action": [
# #         "secretsmanager:GetSecretValue"
# #     ],
# #     "Resource": "*",
# #     "Effect": "Allow",
# #     "Condition": {
# #         "StringEquals": {
# #             "secretsmanager:ResourceTag/SageMaker": "true"
# #         }
# #     }
# # }
# #     ]}"""
# #         )
# #         assert_false(
# #             len(policy.findings) == 0,
# #             "Policy attempts to restrict by tags, but allows any tag to be added",
# #         )

# #         policy = analyze_policy_string(
# #             """{
# #     "Version": "2012-10-17",
# #     "Statement": [
# #         {
# #             "Action": [
# #                 "secretsmanager:ListSecrets"
# #             ],
# #             "Resource": "*",
# #             "Effect": "Allow"
# #         },
# #         {
# #             "Action": [
# #                 "secretsmanager:DescribeSecret",
# #                 "secretsmanager:GetSecretValue",
# #                 "secretsmanager:CreateSecret"
# #             ],
# #             "Resource": [
# #                 "arn:aws:secretsmanager:*:*:secret:AmazonSageMaker-*"
# #             ],
# #             "Effect": "Allow"
# #         },
# #         {
# #             "Action": [
# #                 "secretsmanager:DescribeSecret",
# #                 "secretsmanager:GetSecretValue"
# #             ],
# #             "Resource": "*",
# #             "Effect": "Allow",
# #             "Condition": {
# #                 "StringEquals": {
# #                     "secretsmanager:ResourceTag/SageMaker": "true"
# #                 }
# #             }
# #         }
# #     ]}"""
# #         )
# #         assert_true(len(policy.findings) == 0, "Correct policy")

# #     def test_bad_mfa_policy(self):
# #         # Good policy
# #         policy = analyze_policy_string(
# #             """{
# #     "Version": "2012-10-17",
# #     "Statement": [
# #         {
# #             "Sid": "AllowViewAccountInfo",
# #             "Effect": "Allow",
# #             "Action": "iam:ListVirtualMFADevices",
# #             "Resource": "*"
# #         },
# #         {
# #             "Sid": "AllowManageOwnVirtualMFADevice",
# #             "Effect": "Allow",
# #             "Action": [
# #                 "iam:CreateVirtualMFADevice",
# #                 "iam:DeleteVirtualMFADevice"
# #             ],
# #             "Resource": "arn:aws:iam::*:mfa/${aws:username}"
# #         },
# #         {
# #             "Sid": "AllowManageOwnUserMFA",
# #             "Effect": "Allow",
# #             "Action": [
# #                 "iam:DeactivateMFADevice",
# #                 "iam:EnableMFADevice",
# #                 "iam:GetUser",
# #                 "iam:ListMFADevices",
# #                 "iam:ResyncMFADevice"
# #             ],
# #             "Resource": "arn:aws:iam::*:user/${aws:username}"
# #         },
# #         {
# #             "Sid": "DenyAllExceptListedIfNoMFA",
# #             "Effect": "Deny",
# #             "NotAction": [
# #                 "iam:CreateVirtualMFADevice",
# #                 "iam:EnableMFADevice",
# #                 "iam:GetUser",
# #                 "iam:ListMFADevices",
# #                 "iam:ListVirtualMFADevices",
# #                 "iam:ResyncMFADevice"
# #             ],
# #             "Resource": "*",
# #             "Condition": {
# #                 "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
# #             }
# #         }
# #     ]
# # }"""
# #         )

# #         assert_true(len(policy.findings) == 0, "Good MFA policy")

# #         policy = analyze_policy_string(
# #             """
# #             {
# #     "Version": "2012-10-17",
# #     "Statement": [
# #             {
# #             "Sid": "AllowIndividualUserToManageThierMFA",
# #             "Effect": "Allow",
# #             "Action": [
# #                 "iam:CreateVirtualMFADevice",
# #                 "iam:DeactivateMFADevice",
# #                 "iam:DeleteVirtualMFADevice",
# #                 "iam:EnableMFADevice",
# #                 "iam:ResyncMFADevice"
# #             ],
# #             "Resource": [
# #                 "arn:aws:iam::000000000000:mfa/${aws:username}",
# #                 "arn:aws:iam::000000000000:user/${aws:username}"
# #             ]
# #         },
# #         {
# #             "Sid": "DenyIamAccessToOtherAccountsUnlessMFAd",
# #             "Effect": "Deny",
# #             "Action": [
# #                 "iam:CreateVirtualMFADevice",
# #                 "iam:DeactivateMFADevice",
# #                 "iam:DeleteVirtualMFADevice",
# #                 "iam:EnableMFADevice",
# #                 "iam:ResyncMFADevice",
# #                 "iam:ChangePassword",
# #                 "iam:CreateLoginProfile",
# #                 "iam:DeleteLoginProfile",
# #                 "iam:GetAccountSummary",
# #                 "iam:GetLoginProfile",
# #                 "iam:UpdateLoginProfile"
# #             ],
# #             "NotResource": [
# #                 "arn:aws:iam::000000000000:mfa/${aws:username}",
# #                 "arn:aws:iam::000000000000:user/${aws:username}"
# #             ],
# #             "Condition": {
# #                 "Bool": {
# #                     "aws:MultiFactorAuthPresent": "false"
# #                 }
# #             }
# #         }
# #             ]}"""
# #         )
# #         assert_false(len(policy.findings) == 0, "Bad MFA policy")


def mfa_policy(condition):
    """Policy whose only variable is the Condition block (Action '*' avoids RESOURCE_STAR)."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": condition,
            },
        }
    )


class TestMfaNullCondition:
    """`Null` on aws:MultiFactorAuthPresent must report the same bad pattern as `Bool`.

    The `Null` operator only tests whether a key exists; AWS documents that
    aws:MultiFactorAuthPresent can be present while set to false.
    """

    def test_null_false_reports_bad_pattern(self):
        policy = analyze_policy_string(
            mfa_policy({"Null": {"aws:MultiFactorAuthPresent": "false"}}),
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set(["BAD_PATTERN_FOR_MFA"])
        finding = enhance_finding(policy.findings[0])
        assert finding.issue == "BAD_PATTERN_FOR_MFA"
        assert finding.severity == "MEDIUM"
        assert "Null" in finding.detail
        assert "MultiFactorAuthPresent" in finding.detail
        assert isinstance(finding.location["line"], int)
        assert isinstance(finding.location["column"], int)

    def test_null_false_mixed_case_key(self):
        policy = analyze_policy_string(
            mfa_policy({"Null": {"aWs:mUlTiFaCtOrAuThPrEsEnT": "false"}}),
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set(["BAD_PATTERN_FOR_MFA"])

    def test_null_true_has_no_finding(self):
        policy = analyze_policy_string(
            mfa_policy({"Null": {"aws:MultiFactorAuthPresent": True}}),
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set()

    def test_null_false_other_key_has_no_finding(self):
        policy = analyze_policy_string(
            mfa_policy({"Null": {"aws:SourceVpc": "false"}}),
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set()

    def test_bool_false_control_is_unchanged(self):
        policy = analyze_policy_string(
            mfa_policy({"Bool": {"aws:MultiFactorAuthPresent": "false"}}),
            ignore_private_auditors=True,
        )
        assert policy.finding_ids == set(["BAD_PATTERN_FOR_MFA"])
        assert len(policy.findings) == 1

    def test_cli_exit_code_and_severity_threshold(self, monkeypatch, capsys, tmp_path):
        import parliament.cli as cli

        log_path = tmp_path / "parliament.log"
        real_open = open

        def fake_open(file, *args, **kwargs):
            # parliament.cli logs to the hard-coded POSIX path /tmp/parliament.log;
            # redirect only that path, delegate every other open untouched.
            if str(file).replace("\\", "/").endswith("/tmp/parliament.log"):
                return real_open(log_path, *args, **kwargs)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fake_open)

        class _Stdin:
            name = "<stdin>"

            def isatty(self):
                return False

        monkeypatch.setattr("sys.stdin", _Stdin())
        argv = ["parliament", "--string", mfa_policy({"Null": {"aws:MultiFactorAuthPresent": "false"}})]

        assert cli.main(argv + ["--minimum_severity", "MEDIUM"]) == 1
        assert "MEDIUM - Bad pattern used for MFA check" in capsys.readouterr().out

        assert cli.main(argv + ["--minimum_severity", "HIGH"]) == 0
        assert capsys.readouterr().out.strip() == ""
