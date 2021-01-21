"""
This library is a linter for AWS IAM policies.
"""
__version__ = "1.3.1"

import fnmatch
import functools
import json
import jsoncfg
import re

import pkg_resources
import yaml

# On initialization, load the IAM data
iam_definition_path = pkg_resources.resource_filename(__name__, "iam_definition.json")
iam_definition = json.load(open(iam_definition_path, "r"))

# And the config data
config_path = pkg_resources.resource_filename(__name__, "config.yaml")
config = yaml.safe_load(open(config_path, "r"))


def override_config(override_config_path):
    if override_config_path is None:
        return

    # Load the override file
    override_config = yaml.safe_load(open(override_config_path, "r"))

    # Over-write the settings
    for finding_type, settings in override_config.items():
        if finding_type not in config:
            config[finding_type] = {}
        for setting, setting_value in settings.items():
            config[finding_type][setting] = setting_value


def enhance_finding(finding):
    if finding.issue not in config:
        raise Exception("Uknown finding issue: {}".format(finding.issue))
    config_settings = config[finding.issue]
    finding.severity = config_settings["severity"]
    finding.title = config_settings["title"]
    finding.description = config_settings.get("description", "")
    finding.ignore_locations = config_settings.get("ignore_locations", None)
    return finding


def analyze_policy_string(
    policy_str,
    filepath=None,
    ignore_private_auditors=False,
    private_auditors_custom_path=None,
    include_community_auditors=False,
    config=None,
):
    """Given a string reperesenting a policy, convert it to a Policy object with findings"""

    try:
        # TODO Need to write my own json parser so I can track line numbers. See https://stackoverflow.com/questions/7225056/python-json-decoding-library-which-can-associate-decoded-items-with-original-li
        policy_json = jsoncfg.loads_config(policy_str)
    except jsoncfg.parser.JSONConfigParserException as e:
        policy = Policy(None)
        policy.add_finding("MALFORMED_JSON", detail="json parsing error: {}".format(e), location={'line': e.line, 'column': e.column})
        return policy

    policy = Policy(policy_json, filepath, config)
    policy.analyze(
        ignore_private_auditors,
        private_auditors_custom_path,
        include_community_auditors,
    )
    return policy


class UnknownPrefixException(Exception):
    pass


class UnknownActionException(Exception):
    pass


def is_arn_match(resource_type, arn_format, resource):
    """
    Match the arn_format specified in the docs, with the resource
    given in the IAM policy.  These can each be strings with globbing. For example, we
    want to match the following two strings:
    - arn:*:s3:::*/*
    - arn:aws:s3:::*personalize*

    That should return true because you could have "arn:aws:s3:::personalize/" which matches both.

    Input:
    - resource_type: Example "bucket", this is only used to identify special cases.
    - arn_format: ARN regex from the docs
    - resource: ARN regex from IAM policy

    
    We can cheat some because after the first sections of the arn match, meaning until the 5th colon (with some
    rules there to allow empty or asterisk sections), we only need to match the ID part.
    So the above is simplified to "*/*" and "*personalize*".

    Let's look at some examples and if these should be marked as a match:
    "*/*" and "*personalize*" -> True
    "*", "mybucket" -> True
    "mybucket", "*" -> True
    "*/*", "mybucket" -> False
    "*/*", "mybucket*" -> True
    "*mybucket", "*myotherthing" -> False
    """
    if arn_format == "*" or resource == "*":
        return True

    if "bucket" in resource_type:
        # We have to do a special case here for S3 buckets
        if "/" in resource:
            return False

    # The ARN has at least 6 parts, separated by a colon. Ensure these exist.
    arn_parts = arn_format.split(":")
    if len(arn_parts) < 6:
        raise Exception("Unexpected format for ARN: {}".format(arn_format))
    resource_parts = resource.split(":")
    if len(resource_parts) < 6:
        raise Exception("Unexpected format for resource: {}".format(resource))

    # For the first 5 parts (ex. arn:aws:SERVICE:REGION:ACCOUNT:), ensure these match appropriately
    # We do this because we don't want "arn:*:s3:::*/*" and "arn:aws:logs:*:*:/aws/cloudfront/*" to return True
    for position in range(0, 5):
        if arn_parts[position] == "*" and resource_parts[position] != "":
            continue
        elif resource_parts[position] == "*":
            continue
        elif arn_parts[position] == resource_parts[position]:
            continue
        else:
            return False

    # Everything up to and including the account ID section matches, so now try to match the remainder
    arn_id = ":".join(arn_parts[5:])
    resource_id = ":".join(resource_parts[5:])

    # Some of the arn_id's contain regexes of the form "[key]" so replace those with "*"
    resource_id = re.sub(r"\[.+?\]", "*", resource_id)

    return is_glob_match(arn_id, resource_id)


def is_glob_match(s1, s2):
    # This comes from https://github.com/duo-labs/parliament/issues/36#issuecomment-574001764

    # If strings are equal, TRUE
    if s1 == s2:
        return True
    # If either string is all '*'s, TRUE
    if s1 and all(c == "*" for c in s1) or s2 and all(c == "*" for c in s2):
        return True
    # If either string is '', FALSE (already handled case if both are '' in A)
    if not s1 or not s2:
        return False
    # At this point, we know that both s1 and s2 are non-empty, so safe to access [0]'th element
    # If both strings start with '*', TRUE if match first with remainder of second or second with remainder of first
    if s1[0] == s2[0] == "*":
        return is_glob_match(s1[1:], s2) or is_glob_match(s1, s2[1:])
    # If s1 starts with '*', TRUE if remainder of s1 matches any length remainder of s2
    if s1[0] == "*":
        return any(is_glob_match(s1[1:], s2[i:]) for i in range(len(s2)))
    # If s2 starts with '*', TRUE if remainder of s2 matches any length remainder of s1
    if s2[0] == "*":
        return any(is_glob_match(s1[i:], s2[1:]) for i in range(len(s1)))
    # TRUE if s1 and s2 both have same first element and remainder of s1 matches remainder of s2
    return s1[0] == s2[0] and is_glob_match(s1[1:], s2[1:])


@functools.lru_cache(maxsize=1024)
def expand_action(action, raise_exceptions=True):
    """
    Converts "iam:*List*" to
    [
      {'service':'iam', 'action': 'ListAccessKeys'},
      {'service':'iam', 'action': 'ListUsers'}, ...
    ]
    """
    if action == "*":
        action = "*:*"

    parts = action.split(":")
    if len(parts) != 2:
        raise ValueError("Action should be in form service:action")
    prefix = parts[0]
    unexpanded_action = parts[1]

    actions = []
    service_match = None
    for service in iam_definition:
        if service["prefix"] == prefix.lower() or prefix == "*":
            service_match = service

            if len(service["privileges"]) == 0 and prefix != "*":
                # Service has no privileges, so the action must be *
                # For example iq:*
                if unexpanded_action.lower() == "*":
                    return []

            for privilege in service["privileges"]:
                if fnmatch.fnmatchcase(
                    privilege["privilege"].lower(), unexpanded_action.lower()
                ):
                    actions.append(
                        {
                            "service": service_match["prefix"],
                            "action": privilege["privilege"],
                        }
                    )

    if not service_match and raise_exceptions:
        raise UnknownPrefixException("Unknown prefix {}".format(prefix))

    if len(actions) == 0 and raise_exceptions:
        raise UnknownActionException(
            "Unknown action {}:{}".format(prefix, unexpanded_action)
        )

    return actions


def get_resource_type_matches_from_arn(arn):
    """ Given an ARN such as "arn:aws:s3:::mybucket", find resource types that match it.
        This would return:
        [
            "resource": {
                "arn": "arn:${Partition}:s3:::${BucketName}",
                "condition_keys": [],
                "resource": "bucket"
            },
            "service": {
                "service_name": "Amazon S3",
                "privileges": [...]
                ...
            }
        ]
    """
    matches = []
    for service in iam_definition:
        for resource in service["resources"]:
            arn_format = re.sub(r"\$\{.*?\}", "*", resource["arn"])
            if is_arn_match(resource["resource"], arn, arn_format):
                matches.append({"resource": resource, "service": service})
    return matches


def get_privilege_matches_for_resource_type(resource_type_matches):
    """ Given the response from get_resource_type_matches_from_arn(...), this will identify the relevant privileges.
    """
    privilege_matches = []
    for match in resource_type_matches:
        for privilege in match["service"]["privileges"]:
            for resource_type_dict in privilege["resource_types"]:
                resource_type = resource_type_dict["resource_type"].replace("*", "")
                if resource_type == match["resource"]["resource"]:
                    privilege_matches.append(
                        {
                            "privilege_prefix": match["service"]["prefix"],
                            "privilege_name": privilege["privilege"],
                            "resource_type": resource_type,
                        }
                    )

    return privilege_matches


# Import moved here to deal with cyclic dependency
from .policy import Policy
