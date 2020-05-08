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
    actions = policy.get_allowed_actions()

    credentials_exposure_actions_in_policy = []
    for action in actions:
        if action in CREDENTIALS_EXPOSURE_ACTIONS:
            credentials_exposure_actions_in_policy.append(action)
    if len(credentials_exposure_actions_in_policy) > 0:
        policy.add_finding(
            "CREDENTIALS_EXPOSURE",
            location={"actions": credentials_exposure_actions_in_policy},
        )
