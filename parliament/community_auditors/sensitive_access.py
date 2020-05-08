from collections import defaultdict

from parliament import is_arn_match, expand_action


def _expand_action(operation):
    data = expand_action(operation)[0]

    return "{}:{}".format(data["service"], data["action"])


def audit(policy):
    allowed_actions = policy.get_allowed_actions()

    try:
        config_resources = policy.config["SENSITIVE_ACCESS"]["resources"]
    except KeyError:
        config_resources = {}

    sensitive_resources = defaultdict(list)
    for item in config_resources:
        action = list(item.keys())[0]
        expanded_action = _expand_action(action)
        resources = list(item.values())[0]

        sensitive_resources[expanded_action].extend(resources)

    action_resources = {}
    for action in allowed_actions:
        expanded_action = _expand_action(action)
        service, operation = expanded_action.split(":")
        action_resources[expanded_action] = policy.get_allowed_resources(
            service, operation
        )

    for action in action_resources:
        for action_resource in action_resources[action]:
            for sensitive_resource in sensitive_resources[action]:
                if is_arn_match("object", action_resource, sensitive_resource):
                    policy.add_finding(
                        "SENSITIVE_ACCESS",
                        location={"resource": action_resource, "actions": action},
                    )
