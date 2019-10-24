#!/usr/bin/env python3

import argparse
from os import listdir
from os.path import isfile, join
import sys
import json

from parliament import analyze_policy_string


def print_finding(finding, minimal=False):
    if minimal:
        print("{} - {}".format(finding.severity_name(), finding.issue))
    else:
        print(
            "{} - {} - {}".format(
                finding.severity_name(), finding.issue, finding.location
            )
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--aws-managed-policies",
        help="This is used with the policies directory of https://github.com/SummitRoute/aws_managed_policies",
        type=str,
    )
    parser.add_argument(
        "--auth-details-file",
        help='Provide the path to a file returned by "aws iam get-account-authorization-details"',
        type=str,
    )
    parser.add_argument(
        "--string",
        help='Provide a string such as \'{"Version": "2012-10-17","Statement": {"Effect": "Allow","Action": ["s3:GetObject", "s3:PutBucketPolicy"],"Resource": ["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket2/*"]}}\'',
        type=str,
    )
    parser.add_argument("--file", help="Provide a policy in a file", type=str)
    parser.add_argument(
        "--minimal", help="Minimal output", default=False, action="store_true"
    )
    args = parser.parse_args()

    if args.aws_managed_policies:
        filenames = [
            f
            for f in listdir(args.aws_managed_policies)
            if isfile(join(args.aws_managed_policies, f))
        ]
        for filename in filenames:
            filepath = join(args.aws_managed_policies, filename)
            with open(filepath) as f:
                contents = f.read()
                policy_file_json = json.loads(contents)
                policy_string = json.dumps(
                    policy_file_json["PolicyVersion"]["Document"]
                )
                policy = analyze_policy_string(policy_string, filepath)
                if len(policy.findings) > 0:
                    for finding in policy.findings:
                        print_finding(finding, args.minimal)
    elif args.auth_details_file:
        with open(args.auth_details_file) as f:
            contents = f.read()
            auth_details_json = json.loads(contents)
            for policy in auth_details_json["Policies"]:
                # Ignore AWS defined policies
                if "arn:aws:iam::aws:" not in policy["Arn"]:
                    continue

                for version in policy["PolicyVersionList"]:
                    if not version["IsDefaultVersion"]:
                        continue
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]), policy["Arn"]
                    )
                    for finding in policy.findings:
                        print_finding(finding, args.minimal)

            # Review the inline policies on Users, Roles, and Groups
            for user in auth_details_json["UserDetailList"]:
                for policy in user.get("UserPolicyList", []):
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]), user["Arn"]
                    )
                    for finding in policy.findings:
                        print_finding(finding, args.minimal)
            for role in auth_details_json["RoleDetailList"]:
                for policy in role.get("RolePolicyList", []):
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]), role["Arn"]
                    )
                    for finding in policy.findings:
                        print_finding(finding, args.minimal)
            for group in auth_details_json["GroupDetailList"]:
                for policy in group.get("GroupPolicyList", []):
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]), group["Arn"]
                    )
                    for finding in policy.findings:
                        print_finding(finding, args.minimal)
    elif args.string:
        policy = analyze_policy_string(args.string)
        for finding in policy.findings:
            print_finding(finding, args.minimal)
    elif args.file:
        with open(args.file) as f:
            contents = f.read()
            policy = analyze_policy_string(contents)
            for finding in policy.findings:
                print_finding(finding, args.minimal)
    else:
        parser.print_help()
        exit(-1)


if __name__ == "__main__":
    main()
