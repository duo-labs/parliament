def audit(policy):
    actions = policy.get_allowed_actions()
    permissions_on_other_users(policy, actions)


# Categories based on https://know.bishopfox.com/blog/5-privesc-attack-vectors-in-aws


def permissions_on_other_users(policy, expanded_actions):
    # Turn into lowercase
    expanded_actions_normalized = [x.lower() for x in expanded_actions]
    expanded_actions = set(expanded_actions_normalized)

    escalation_methods = {
        # 1. IAM Permissions on Other Users
        "CreateAccessKey": ["iam:createaccesskey"],
        "CreateLoginProfile": ["iam:createloginprofile"],
        "UpdateLoginProfile": ["iam:updateloginprofile"],
        # 2. Permissions on Policies
        "CreateNewPolicyVersion": ["iam:createpolicyversion"],
        "SetExistingDefaultPolicyVersion": ["iam:setdefaultpolicyversion"],
        "AttachUserPolicy": ["iam:attachuserpolicy"],
        "AttachGroupPolicy": ["iam:attachgrouppolicy"],
        "AttachRolePolicy": ["iam:attachrolepolicy", "sts:assumerole"],
        "PutUserPolicy": ["iam:putuserpolicy"],
        "PutGroupPolicy": ["iam:putgrouppolicy"],
        "PutRolePolicy": ["iam:putrolepolicy", "sts:assumerole"],
        "AddUserToGroup": ["iam:addusertogroup"],
        # 3. Updating an AssumeRolePolicy
        "UpdateRolePolicyToAssumeIt": ["iam:updateassumerolepolicy", "sts:assumerole"],
        # 4. iam:PassRole:*
        "CreateEC2WithExistingIP": ["iam:passrole", "ec2:runinstances"],
        "PassExistingRoleToNewLambdaThenInvoke": [
            "iam:passrole",
            "lambda:createfunction",
            "lambda:invokefunction",
        ],
        "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": [
            "iam:passrole",
            "lambda:createfunction",
            "lambda:createeventsourcemapping",
            "dynamodb:createtable",
            "dynamodb:putitem",
        ],
        "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": [
            "iam:passrole",
            "lambda:createfunction",
            "lambda:createeventsourcemapping",
        ],
        "PassExistingRoleToNewGlueDevEndpoint": [
            "iam:passrole",
            "glue:createdevendpoint",
        ],
        "PassExistingRoleToCloudFormation": [
            "iam:passrole",
            "cloudformation:createstack",
        ],
        "PassExistingRoleToNewDataPipeline": [
            "iam:passrole",
            "datapipeline:createpipeline",
        ],
        # 5. Privilege Escalation Using AWS Services
        "UpdateExistingGlueDevEndpoint": ["glue:updatedevendpoint"],
        "EditExistingLambdaFunctionWithRole": ["lambda:updatefunctioncode"],
    }

    for key in escalation_methods:
        if set(escalation_methods[key]).issubset(expanded_actions):
            policy.add_finding(
                "PRIVILEGE_ESCALATION",
                location={"type": key, "actions": escalation_methods[key]},
            )
