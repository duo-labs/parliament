# https://github.com/awslabs/aws-cloudsaga
IMDSv1_REVEAL = [
"ec2:DescribeInstances"
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

    imdsv1_reveal_in_policy = []
    for action in actions:
        if action in IMDSv1_REVEAL:
            imdsv1_reveal_in_policy.append(action)
    if len(imdsv1_reveal_in_policy) > 0:
        policy.add_finding(
            "IMDSv1_REVEAL",
            location={"actions": imdsv1_reveal_in_policy},
        )
