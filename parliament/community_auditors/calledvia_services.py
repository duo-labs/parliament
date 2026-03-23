"""
Validate that aws:CalledVia, aws:CalledViaFirst, and aws:CalledViaLast condition
keys only reference services documented by AWS as supporting CalledVia.

See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-calledvia

Fixes https://github.com/duo-labs/parliament/issues/84
"""
from parliament import Policy
from parliament.misc import make_list


# Services documented by AWS as supporting CalledVia
CALLEDVIA_SUPPORTED_SERVICES = {
    "athena.amazonaws.com",
    "cloudformation.amazonaws.com",
    "databrew.amazonaws.com",
    "dynamodb.amazonaws.com",
    "kms.amazonaws.com",
    "macie.amazonaws.com",
    "ram.amazonaws.com",
    "rolesanywhere.amazonaws.com",
    "s3.amazonaws.com",
}

CALLEDVIA_CONDITION_KEYS = [
    "aws:calledvia",
    "aws:calledviafirst",
    "aws:calledvialast",
]


def audit(policy: Policy) -> None:
    for stmt in policy.statements:
        if "Condition" not in stmt.stmt:
            continue

        conditions = stmt.stmt["Condition"]
        for condition in conditions:
            condition_block = condition[1]

            for block in condition_block:
                key = block[0]
                if key.lower() not in CALLEDVIA_CONDITION_KEYS:
                    continue

                values = []
                for v in make_list(block[1]):
                    values.append(v.value)

                for value in values:
                    if value.lower() not in CALLEDVIA_SUPPORTED_SERVICES:
                        policy.add_finding(
                            "INVALID_CALLEDVIA_SERVICE",
                            detail="Service {} is not in the list of services that support aws:CalledVia. Supported services: {}".format(
                                value, ", ".join(CALLEDVIA_SUPPORTED_SERVICES)
                            ),
                        )
