# https://github.com/awslabs/aws-cloudsaga
IAM_CREDENTIALS = [
"ec2:DescribeInstances",
"ec2:RunInstances"
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

    iam_credentials_in_policy = []
    for action in actions:
        if action in IAM_CREDENTIALS:
            iam_credentials_in_policy.append(action)
    if len(iam_credentials_in_policy) > 0:
        policy.add_finding(
            "IAM_CREDENTIALS",
            location={"actions": iam_credentials_in_policy},
        )
