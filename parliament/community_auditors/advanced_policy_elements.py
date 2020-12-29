""" 
For AWS resource policies, check whether they use discouraged constructions.
See the [AWS Policy Troubleshooting Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_policies.html).

AWS documentation discourages the use of NotPrincipal, NotAction and
NotResource, particularly with Allow. These constructs, by default, grant 
permissions, then Deny the ones explicitly listed. Instead, use an explicit 
Resource, Action or Principal in your Allow list.
"""

from typing import Iterable

import jsoncfg

from parliament import Policy


def get_stmts(policy: Policy) -> Iterable:
    if "jsoncfg.config_classes.ConfigJSONObject" in str(
        type(policy.policy_json.Statement)
    ):
        return [policy.policy_json.Statement]
    elif "jsoncfg.config_classes.ConfigJSONArray" in str(
        type(policy.policy_json.Statement)
    ):
        return policy.policy_json.Statement


def audit(policy: Policy) -> None:
    for stmt in get_stmts(policy):
        if stmt.Effect.value == "Allow" and jsoncfg.node_exists(stmt["NotPrincipal"]):
            # See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html#specifying-notprincipal-allow
            policy.add_finding(
                "NOTPRINCIPAL_WITH_ALLOW",
                location=("NotPrincipal", stmt["NotPrincipal"]),
            )
        elif stmt.Effect.value == "Allow" and jsoncfg.node_exists(stmt["NotResource"]):
            # See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html#notresource-element-combinations
            policy.add_finding(
                "NOTRESOURCE_WITH_ALLOW",
                location=("NotResource", stmt["NotResource"]),
            )
