"""
For AWS policies using conditionals, checking a single valued condition key with a check
designed for multi-value condition keys results in "overly permissive policies"
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_single-vs-multi-valued-condition-keys.html
"""
import re
from parliament import Policy
from parliament.misc import make_list

def audit(policy: Policy) -> None:
    global_single_valued_condition_keys = [
        "aws:CalledViaFirst",
        "aws:CalledViaLast",
        "aws:CurrentTime",
        "aws:EpochTime",
        "aws:FederatedProvider",
        "aws:MultiFactorAuthAge",
        "aws:MultiFactorAuthPresent",
        "aws:PrincipalAccount",
        "aws:PrincipalArn",
        "aws:PrincipalIsAWSService",
        "aws:PrincipalOrgID",
        "aws:PrincipalServiceName",
        "aws:PrincipalTag",
        "aws:PrincipalType",
        "aws:referer",
        "aws:RequestedRegion",
        "aws:RequestTag/*",
        "aws:ResourceTag/*",
        "aws:SecureTransport",
        "aws:SourceAccount",
        "aws:SourceArn",
        "aws:SourceIdentity",
        "aws:SourceIp",
        "aws:SourceVpc",
        "aws:SourceVpce",
        "aws:TokenIssueTime",
        "aws:UserAgent",
        "aws:userid",
        "aws:username",
        "aws:ViaAWSService",
        "aws:VpcSourceIp",
    ]

    for stmt in policy.statements:
        if "Condition" not in stmt.stmt:
            return

        conditions = stmt.stmt["Condition"]
        for condition in conditions:
            # The operator is the first element (ex. `StringLike`) and the condition_block follows it
            operator = condition[0]
            condition_block = condition[1]
            if re.match(r"^For(All|Any)Values:", operator):
                keys = list(k for k,_v in condition_block)
                if any(any(re.match(k, key) for k in global_single_valued_condition_keys) for key in keys):
                    policy.add_finding(
                        "SINGLE_VALUE_CONDITION_TOO_PERMISSIVE",
                        detail='Checking a single value conditional key against a set of values results in overly permissive policies.',
                    )
