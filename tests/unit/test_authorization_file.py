import unittest
import jsoncfg
import json
from parliament import analyze_policy_string


class TestAuthDetailsFile(unittest.TestCase):
    def test_auth_details_example(self):
        auth_details_json = {
            "UserDetailList": [
                {
                    "Path": "/",
                    "UserName": "obama",
                    "UserId": "YAAAAASSQUEEEN",
                    "Arn": "arn:aws:iam::012345678901:user/obama",
                    "CreateDate": "2019-12-18 19:10:08+00:00",
                    "GroupList": ["admin"],
                    "AttachedManagedPolicies": [],
                    "Tags": [],
                }
            ],
            "GroupDetailList": [
                {
                    "Path": "/",
                    "GroupName": "admin",
                    "GroupId": "YAAAAASSQUEEEN",
                    "Arn": "arn:aws:iam::012345678901:group/admin",
                    "CreateDate": "2017-05-15 17:33:36+00:00",
                    "GroupPolicyList": [],
                    "AttachedManagedPolicies": [
                        {
                            "PolicyName": "AdministratorAccess",
                            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        }
                    ],
                }
            ],
            "RoleDetailList": [
                {
                    "Path": "/",
                    "RoleName": "MyRole",
                    "RoleId": "YAAAAASSQUEEEN",
                    "Arn": "arn:aws:iam::012345678901:role/MyRole",
                    "CreateDate": "2019-08-16 17:27:59+00:00",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ssm.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "InstanceProfileList": [],
                    "RolePolicyList": [
                        {
                            "PolicyName": "Stuff",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Action": [
                                            "s3:ListBucket",
                                            "s3:Put*",
                                            "s3:Get*",
                                            "s3:*MultipartUpload*",
                                        ],
                                        "Resource": ["*"],
                                        "Effect": "Allow",
                                    }
                                ],
                            },
                        }
                    ],
                    "AttachedManagedPolicies": [],
                    "Tags": [],
                    "RoleLastUsed": {},
                },
                {
                    "Path": "/",
                    "RoleName": "MyOtherRole",
                    "RoleId": "YAAAAASSQUEEEN",
                    "Arn": "arn:aws:iam::012345678901:role/MyOtherRole",
                    "CreateDate": "2019-08-16 17:27:59+00:00",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ssm.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "InstanceProfileList": [],
                    "RolePolicyList": [
                        {
                            "PolicyName": "SupYo",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "VisualEditor0",
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:PutBucketPolicy",
                                            "s3:PutBucketAcl",
                                            "s3:PutLifecycleConfiguration",
                                            "s3:PutObject",
                                            "s3:GetObject",
                                            "s3:DeleteObject",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "AttachedManagedPolicies": [],
                    "Tags": [],
                    "RoleLastUsed": {},
                },
            ],
            "Policies": [
                {
                    "PolicyName": "NotYourPolicy",
                    "PolicyId": "YAAAAASSQUEEEN",
                    "Arn": "arn:aws:iam::012345678901:policy/NotYourPolicy",
                    "Path": "/",
                    "DefaultVersionId": "v9",
                    "AttachmentCount": 1,
                    "PermissionsBoundaryUsageCount": 0,
                    "IsAttachable": True,
                    "CreateDate": "2020-01-29 21:24:20+00:00",
                    "UpdateDate": "2020-01-29 23:23:12+00:00",
                    "PolicyVersionList": [
                        {
                            "Document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "VisualEditor0",
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:PutBucketPolicy",
                                            "s3:PutBucketAcl",
                                            "s3:PutLifecycleConfiguration",
                                            "s3:PutObject",
                                            "s3:GetObject",
                                            "s3:DeleteObject",
                                        ],
                                        "Resource": [
                                            "arn:aws:s3:::mybucket/*",
                                            "arn:aws:s3:::mybucket",
                                        ],
                                    }
                                ],
                            },
                            "VersionId": "v9",
                            "IsDefaultVersion": True,
                            "CreateDate": "2020-01-29 23:23:12+00:00",
                        }
                    ],
                }
            ],
        }
        findings = []
        for policy in auth_details_json["Policies"]:
            # Ignore AWS defined policies
            if "arn:aws:iam::aws:" not in policy["Arn"]:
                continue
            if (
                policy["Path"] == "/service-role/"
                or policy["Path"] == "/aws-service-role/"
                or policy["PolicyName"].startswith("AWSServiceRoleFor")
                or policy["PolicyName"].endswith("ServiceRolePolicy")
                or policy["PolicyName"].endswith("ServiceLinkedRolePolicy")
            ):
                continue

            for version in policy["PolicyVersionList"]:
                if not version["IsDefaultVersion"]:
                    continue
                print(version["Document"])
                policy = analyze_policy_string(
                    json.dumps(version["Document"]), policy["Arn"],
                )
                findings.extend(policy.findings)

        # Review the inline policies on Users, Roles, and Groups
        for user in auth_details_json["UserDetailList"]:
            for policy in user.get("UserPolicyList", []):
                policy = analyze_policy_string(
                    json.dumps(policy["PolicyDocument"]),
                    user["Arn"],
                    private_auditors_custom_path=None,
                )
                findings.extend(policy.findings)
        for role in auth_details_json["RoleDetailList"]:
            for policy in role.get("RolePolicyList", []):
                policy = analyze_policy_string(
                    json.dumps(policy["PolicyDocument"]),
                    role["Arn"],
                    private_auditors_custom_path=None,
                )
                findings.extend(policy.findings)
        for group in auth_details_json["GroupDetailList"]:
            for policy in group.get("GroupPolicyList", []):
                policy = analyze_policy_string(
                    json.dumps(policy["PolicyDocument"]),
                    group["Arn"],
                    private_auditors_custom_path=None,
                )
                findings.extend(policy.findings)

        self.maxDiff = None
        self.assertTrue("RESOURCE_POLICY_PRIVILEGE_ESCALATION" in str(findings))
