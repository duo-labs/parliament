from policy_sentry.shared.database import connect_db
from policy_sentry.util.policy_files import get_actions_from_policy
from policy_sentry.analysis.analyze import determine_actions_to_expand


def audit(policy):
    db_session = connect_db('bundled')
    actions_in_policy = get_actions_from_policy(policy.policy_json)
    expanded_actions = determine_actions_to_expand(db_session, actions_in_policy)
    permissions_on_other_users(policy, expanded_actions)


# Categories based on https://know.bishopfox.com/blog/5-privesc-attack-vectors-in-aws

def permissions_on_other_users(policy, expanded_actions):
    escalation_methods = {
        # 1. IAM Permissions on Other Users
        'CreateAccessKey': [
            'iam:createaccesskey'
        ],
        'CreateLoginProfile': [
            'iam:createloginprofile'
        ],
        'UpdateLoginProfile': [
            'iam:updateloginprofile'
        ],
        # 2. Permissions on Policies
        'CreateNewPolicyVersion': [
            'iam:createpolicyversion'
        ],
        'SetExistingDefaultPolicyVersion': [
            'iam:setdefaultpolicyversion'
        ],
        'AttachUserPolicy': [
            'iam:attachuserpolicy'
        ],
        'AttachGroupPolicy': [
            'iam:attachgrouppolicy'
        ],
        'AttachRolePolicy': [
            'iam:attachrolepolicy',
            'sts:assumerole'
        ],
        'PutUserPolicy': [
            'iam:putuserpolicy'
        ],
        'PutGroupPolicy': [
            'iam:putgrouppolicy'
        ],
        'PutRolePolicy': [
            'iam:putrolepolicy',
            'sts:assumerole'
        ],
        'AddUserToGroup': [
            'iam:addusertogroup'
        ],
        # 3. Updating an AssumeRolePolicy
        'UpdateRolePolicyToAssumeIt': [
            'iam:updateassumerolepolicy',
            'sts:assumerole'
        ],
        # 4. iam:PassRole:*
        'CreateEC2WithExistingIP': [
            'iam:passrole',
            'ec2:runinstances'
        ],
        'PassExistingRoleToNewLambdaThenInvoke': [
            'iam:passrole',
            'lambda:createfunction',
            'lambda:invokefunction'
        ],
        'PassExistingRoleToNewLambdaThenTriggerWithNewDynamo': [
            'iam:passrole',
            'lambda:createfunction',
            'lambda:createeventsourcemapping',
            'dynamodb:createtable',
            'dynamodb:putitem'
        ],
        'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo': [
            'iam:passrole',
            'lambda:createfunction',
            'lambda:createeventsourcemapping'
        ],
        'PassExistingRoleToNewGlueDevEndpoint': [
            'iam:passrole',
            'glue:createdevendpoint'
        ],
        'PassExistingRoleToCloudFormation': [
            'iam:passrole',
            'cloudformation:createstack'
        ],
        'PassExistingRoleToNewDataPipeline': [
            'iam:passrole',
            'datapipeline:createpipeline'
        ],
        # 5. Privilege Escalation Using AWS Services
        'UpdateExistingGlueDevEndpoint': [
            'glue:updatedevendpoint'
        ],
        'EditExistingLambdaFunctionWithRole': [
            'lambda:updatefunctioncode'
        ]
    }
    for key in escalation_methods:
        # turn into lowercase
        # [x.lower() for x in escalation_methods[key]]
        if set(escalation_methods[key]).issubset(set(expanded_actions)):
            policy.add_finding("PRIVILEGE_ESCALATION", location={"type": key, "actions": escalation_methods[key]})

