#!/usr/bin/env python3

import argparse
from os import listdir
from os.path import isfile, join
import sys
import json
import re

from parliament import analyze_policy_string, enhance_finding, override_config
from parliament.misc import make_list


def is_finding_filtered(finding, minimum_severity="LOW"):
    # Return True if the finding should be filtered (ie. return False if it should be displayed)
    minimum_severity = minimum_severity.upper()
    severity_choices = ["MUTE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity_choices.index(finding.severity) < severity_choices.index(
        minimum_severity
    ):
        return True

    if finding.ignore_locations:
        # The ignore_locations element looks like this:
        #
        # ignore_locations:
        # - filepath: "test.json"
        #   action: "s3:GetObject"
        #   resource:
        #   - "a"
        #   - "b"
        # - action: "s3:GetObject"
        #   resource:
        #    - "c.*"
        #
        # Assuming the finding has these types of values in the `location` element,
        # this will ignore any finding that matches the filepath to "test.json"
        # AND action to "s3:GetObject"
        # AND the resource to "a" OR "b"
        # It will also ignore a resource that matches "c.*".

        for ignore_location in finding.ignore_locations:
            all_match = True
            for location_type, locations_to_ignore in ignore_location.items():
                has_array_match = False
                for location_to_ignore in make_list(locations_to_ignore):
                    if re.fullmatch(
                        location_to_ignore.lower(),
                        str(finding.location.get(location_type, "")).lower(),
                    ):
                        has_array_match = True
                if not has_array_match:
                    all_match = False
            if all_match:
                return True
    return False


def print_finding(finding, minimal_output=False, json_output=False):
    if minimal_output:
        print("{}".format(finding.issue))
    elif json_output:
        print(
            json.dumps(
                {
                    "issue": finding.issue,
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "detail": finding.detail,
                    "location": finding.location,
                }
            )
        )
    else:
        print(
            "{} - {} - {} - {} - {}".format(
                finding.severity,
                finding.title,
                finding.description,
                finding.detail,
                finding.location,
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
    parser.add_argument(
        "--json", help="json output", default=False, action="store_true"
    )
    parser.add_argument(
        "--minimum_severity",
        help="Minimum severity to display. Options: CRITICAL, HIGH, MEDIUM, LOW, INFO",
        default="LOW",
    )
    parser.add_argument(
        "--private_auditors",
        help="Directory of the private auditors. Defaults to looking in private_auditors in the same directory as the iam_definition.json file.",
        default=None,
    )
    parser.add_argument(
        "--config", help="Custom config file for over-riding values", type=str
    )
    args = parser.parse_args()

    if args.private_auditors is not None and "." in args.private_auditors:
        raise Exception("The path to the private_auditors must not have periods")

    if args.minimal and args.json:
        raise Exception("You cannot choose both minimal and json output")

    # Change the exit status if there are errors
    exit_status = 0
    findings = []

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
                policy = analyze_policy_string(
                    policy_string,
                    filepath,
                    private_auditors_custom_path=args.private_auditors,
                )
                findings.extend(policy.findings)

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
                        json.dumps(version["Document"]), policy["Arn"],
                    )
                    findings.extend(policy.findings)

            # Review the inline policies on Users, Roles, and Groups
            for user in auth_details_json["UserDetailList"]:
                for policy in user.get("UserPolicyList", []):
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]),
                        user["Arn"],
                        private_auditors_custom_path=args.private_auditors,
                    )
                    findings.extend(policy.findings)
            for role in auth_details_json["RoleDetailList"]:
                for policy in role.get("RolePolicyList", []):
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]),
                        role["Arn"],
                        private_auditors_custom_path=args.private_auditors,
                    )
                    findings.extend(policy.findings)
            for group in auth_details_json["GroupDetailList"]:
                for policy in group.get("GroupPolicyList", []):
                    policy = analyze_policy_string(
                        json.dumps(version["Document"]),
                        group["Arn"],
                        private_auditors_custom_path=args.private_auditors,
                    )
                    findings.extend(policy.findings)
    elif args.string:
        policy = analyze_policy_string(
            args.string, private_auditors_custom_path=args.private_auditors
        )
        findings.extend(policy.findings)
    elif args.file:
        with open(args.file) as f:
            contents = f.read()
            policy = analyze_policy_string(
                contents, args.file, private_auditors_custom_path=args.private_auditors
            )
            findings.extend(policy.findings)
    else:
        parser.print_help()
        exit(-1)

    filtered_findings = []
    override_config(args.config)
    for finding in findings:
        finding = enhance_finding(finding)
        if not is_finding_filtered(finding, args.minimum_severity):
            filtered_findings.append(finding)

    if len(filtered_findings) == 0:
        # Return with exit code 0 if no findings
        return

    for finding in filtered_findings:
        print_finding(finding, args.minimal, args.json)

    # There were findings, so return with a non-zero exit code
    exit(1)


if __name__ == "__main__":
    main()
