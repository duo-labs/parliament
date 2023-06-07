# https://github.com/awslabs/aws-cloudsaga
NETWORK_CHANGES = [
"ec2:DescribeInstances",
"ec2:RunInstances",
"ec2:CreateVpc",
"ec2:DescribeVpcs",
"ec2:CreateSecurityGroup"
]


# def credential_exposure_audit(policy):
#     actions = policy.get_allowed_actions()
#     credentials_exposure_actions_in_policy = []
#
#     for action in actions:
#         if action in CREDENTIALS_EXPOSURE_ACTIONS:
#             credentials_exposure_actions_in_policy.append(action)
#     if len(credentials_exposure_actions_in_policy) > 0:
#         return True, credentials_exposure_actions_in_policy
#     return False

def audit(policy):
    actions = policy.get_allowed_actions()

    network_changes_in_policy = []
    for action in actions:
        if action in NETWORK_CHANGES:
            network_changes_in_policy.append(action)
    if len(network_changes_in_policy) > 0:
        policy.add_finding(
            "NETWORK_CHANGES",
            location={"actions": network_changes_in_policy},
        )
