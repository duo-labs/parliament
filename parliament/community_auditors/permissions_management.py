from parliament import is_arn_match, expand_action
from policy_sentry.shared.database import connect_db
from policy_sentry.querying.actions import get_actions_with_access_level
from policy_sentry.util.policy_files import get_actions_from_policy
from policy_sentry.analysis.analyze import determine_actions_to_expand


def audit(policy):
    db_session = connect_db('bundled')
    permissions_management_actions = get_actions_with_access_level(db_session, "all", "Permissions management")
    actions_in_policy = get_actions_from_policy(policy.policy_json)
    permissions_management_actions_in_policy = []
    actions = determine_actions_to_expand(db_session, actions_in_policy)
    for action in actions:
        if action in permissions_management_actions:
            permissions_management_actions_in_policy.append(action)
            # print(f"Permissions management actions: {action}")
    if len(permissions_management_actions_in_policy) > 0:
        policy.add_finding("PERMISSIONS_MANAGEMENT_ACTIONS",
                           location={"actions": permissions_management_actions_in_policy})
