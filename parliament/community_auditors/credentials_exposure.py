from parliament import is_arn_match, expand_action
from policy_sentry.shared.database import connect_db
from policy_sentry.querying.actions import get_actions_with_access_level
from policy_sentry.util.policy_files import get_actions_from_policy
from policy_sentry.analysis.analyze import determine_actions_to_expand

# https://gist.github.com/kmcquade/33860a617e651104d243c324ddf7992a
CREDENTIALS_EXPOSURE_ACTIONS = [
    "codepipeline:pollforjobs",
    "cognito-idp:associatesoftwaretoken",
    "cognito-identity:getopenidtoken",
    "cognito-identity:getopenidtokenfordeveloperidentity",
    "cognito-identity:getcredentialsforidentity",
    "connect:getfederationtoken",
    "connect:getfederationtokens",
    "ecr:getauthorizationtoken",
    "gamelift:requestuploadcredentials",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:createservicespecificcredential",
    "iam:resetservicespecificcredential",
    "iam:updateaccesskey",
    "iot:assumerolewithcertificate",
    "lightsail:getinstanceaccessdetails",
    "lightsail:getrelationaldatabasemasteruserpassword",
    "rds-db:connect",
    "redshift:getclustercredentials",
    "sso:getrolecredentials",
    "mediapackage:rotateingestendpointcredentials",
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
    "sts:getfederationtoken",
    "sts:getsessiontoken",
]


def audit(policy):
    db_session = connect_db('bundled')
    actions_in_policy = get_actions_from_policy(policy.policy_json)
    actions = determine_actions_to_expand(db_session, actions_in_policy)
    credentials_exposure_actions_in_policy = []
    for action in actions:
        if action in CREDENTIALS_EXPOSURE_ACTIONS:
            credentials_exposure_actions_in_policy.append(action)
    if len(credentials_exposure_actions_in_policy) > 0:
        policy.add_finding("CREDENTIALS_EXPOSURE",
                           location={"actions": credentials_exposure_actions_in_policy})

