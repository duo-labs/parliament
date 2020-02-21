from parliament import is_arn_match, expand_action
from policy_sentry.shared.database import connect_db
from policy_sentry.querying.actions import get_actions_with_access_level


def audit(policy):
    db_session = connect_db("bundled")
    permissions_management_actions = get_actions_with_access_level(
        db_session, "all", "Permissions management"
    )
    permissions_management_actions_normalized = [
        x.lower() for x in permissions_management_actions
    ]
    permissions_management_actions = permissions_management_actions_normalized

    actions = policy.get_allowed_actions()

    permissions_management_actions_in_policy = []
    for action in actions:
        if action in permissions_management_actions:
            permissions_management_actions_in_policy.append(action)
    if len(permissions_management_actions_in_policy) > 0:
        policy.add_finding(
            "PERMISSIONS_MANAGEMENT_ACTIONS",
            location={"actions": permissions_management_actions_in_policy},
        )
