import jsoncfg
import re

from . import (
    iam_definition,
    is_arn_match,
    expand_action,
    UnknownActionException,
    UnknownPrefixException,
)
from .finding import Finding
from .misc import make_list


def is_condition_key_match(document_key, str):
    """ Given a documented condition key and one from a policy, determine if they match
    Examples:
    - s3:prefix and s3:prefix obviously match
    - s3:ExistingObjectTag/<key> and s3:ExistingObjectTag/backup match
    """

    # Normalize both
    document_key = document_key.lower()
    str = str.lower()

    # Check if the document key has a pattern match in it
    if "$" in document_key:
        # Some services use a format like license-manager:ResourceTag/${TagKey}
        if str.startswith(document_key.split("$")[0]):
            return True
    elif "<" in document_key:
        # Some services use a format like s3:ExistingObjectTag/<key>
        if str.startswith(document_key.split("<")[0]):
            return True
    elif "tag-key" in document_key:
        # Some services use a format like secretsmanager:ResourceTag/tag-key
        if str.startswith(document_key.split("tag-key")[0]):
            return True

    # Just return whether they match exactly
    return document_key == str


def get_privilege_info(service, action):
    """
    Given a service, like "s3"
    and an action, like "ListBucket"
    return the info from the docs about that action, along with some of the info from the docs
    """
    for service_info in iam_definition:
        if service_info["prefix"] == service:
            for privilege_info in service_info["privileges"]:
                if privilege_info["privilege"] == action:
                    privilege_info["service_resources"] = service_info["resources"]
                    privilege_info["service_conditions"] = service_info["conditions"]
                    return privilege_info
    raise UnknownActionException("Unknown action {}:{}".format(service, action))


def get_arn_format(resource_type, service_resources):
    """
    Search through the service_resources for the given resource_type.
    Example, a resource_type of "object*", given the S3 resources,
    should return "arn:.*?:s3:::.*?/.*?"

    Raises an exception if the resource_type cannot be found.
    """
    # Get rid of the asterisk
    resource_type = resource_type.replace("*", "")

    # Search through the resource service resources for this resource type
    for resource_definition in service_resources:
        if resource_type == resource_definition["resource"]:
            # The resource["arn"] looks like "arn:${Partition}:s3:::${BucketName}/${ObjectName}"
            # We need it to look like "arn:.*?:s3:::.*?/.*?" for matching
            # This does a minimal (non-greedy) match
            arn_format = re.sub(r"\$\{.*?\}", "*", resource_definition["arn"])

            # Get the compiled regex
            return arn_format

    raise Exception(
        "Could not find the resource type {} in the service definition. {}".format(
            resource_type, service_resources
        )
    )


def is_valid_region(str):
    region_regex = re.compile("^([a-z]{2}|us-gov)-[a-z]+-[0-9]$")
    if str == "" or str == "*" or region_regex.match(str):
        return True
    return False


def is_valid_account_id(str):
    # TODO I may want to check for common place holder values for account ids,
    # such as 000000000000 and 123456789012
    account_id_regex = re.compile("^[0-9]{12}$")
    if str == "" or str == "*" or account_id_regex.match(str):
        return True
    return False


OPERATORS = {
    # String
    "StringEquals": "String",
    "StringNotEquals": "String",
    "StringEqualsIgnoreCase": "String",
    "StringNotEqualsIgnoreCase": "String",
    "StringLike": "String",
    "StringNotLike": "String",
    # Number
    "NumericEquals": "Number",
    "NumericNotEquals": "Number",
    "NumericLessThan": "Number",
    "NumericLessThanEquals": "Number",
    "NumericGreaterThan": "Number",
    "NumericGreaterThanEquals": "Number",
    # Date
    "DateEquals": "Date",
    "DateNotEquals": "Date",
    "DateLessThan": "Date",
    "DateLessThanEquals": "Date",
    "DateGreaterThan": "Date",
    "DateGreaterThanEquals": "Date",
    # Bool
    "Bool": "Bool",
    "Null": "Bool",
    # Binary
    "BinaryEquals": "Binary",
    # Ip
    "IpAddress": "Ip",
    "NotIpAddress": "Ip",
    # Arn
    "ArnEquals": "Arn",
    "ArnLike": "Arn",
    "ArnNotEquals": "Arn",
    "ArnNotLike": "Arn",
}

GLOBAL_CONDITION_KEYS = {
    "aws:CalledVia": "String",
    "aws:CalledViaFirst": "String",
    "aws:CalledViaLast": "String",
    "aws:CurrentTime": "Date",
    "aws:EpochTime": "Date",  # This needs to accept Date or Numeric
    "aws:MultiFactorAuthAge": "Numeric",
    "aws:MultiFactorAuthPresent": "Bool",
    "aws:PrincipalOrgID": "String",
    "aws:PrincipalArn": "Arn",
    "aws:RequestedRegion": "String",
    "aws:SecureTransport": "Bool",
    "aws:UserAgent": "String",
    # Keys Available for Some Services
    "aws:PrincipalTag/*": "String",
    "aws:PrincipalType": "String",
    "aws:Referer": "String",
    "aws:RequestTag/*": "String",
    "aws:ResourceTag/*": "String",
    "aws:SourceAccount": "String",
    "aws:SourceArn": "Arn",
    "aws:SourceIp": "Ip",
    "aws:SourceVpc": "String",
    "aws:SourceVpce": "String",
    "aws:TagKeys": "String",
    "aws:TokenIssueTime": "Date",
    "aws:userid": "String",
    "aws:username": "String",
    "aws:VpcSourceIp": "Ip",
}


def get_global_key_type(str):
    """
    Given a global key, return it's type, or None if not found.
    Examples:
    "aws:CurrentTime" -> "Date"
    "aws:currenttime" -> "Date"
    "test" -> None
    """

    str = str.lower()
    for key in GLOBAL_CONDITION_KEYS:
        if "*" in key:
            if str.startswith(key.split("*")[0].lower()):
                return GLOBAL_CONDITION_KEYS[key]
        elif str == key.lower():
            return GLOBAL_CONDITION_KEYS[key]
    return None


def is_value_in_correct_format_for_type(type_needed, values):
    """
    Given a documented type needed such as "Arn", return True if all values match.

    For example, if you have a condition of:
    "Condition": {"DateGreaterThan" :{"aws:CurrentTime" : "2019-07-16T12:00:00Z"}} 

    Then this function would end up being called with:
    - type_needed: Date
    - values: ["2019-07-16T12:00:00Z"]
    This would return True.
    """
    type_needed = translate_documentation_types(type_needed)

    regex_patterns = {
        "Arn": "^arn:.*:.*:.*:.*:.*$",
        # Binary is a base64 encoded value, like "QmluYXJ5VmFsdWVJbkJhc2U2NA=="
        "Binary": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
        "Bool": "^(true)|(false)$",
        "Date": "^\d{4}-\d{2}-\d{2}T\d\d:\d\d:\d\dZ$",
        # Ip is either IPv4 or IPv6 (ex. 203.0.113.0/24 or 2001:DB8:1234:5678::/64)
        # and may not have a range specified (ex. /32)
        "Ip": "^(\d+.\d+.\d+.\d+(/\d+)?)|\d*:\d*:\d*:\d*:\d*:\d*(/\d+)?$",
        "Number": "^\d+$",
        "String": ".*",  # Strings can be anything
    }

    for value in values:
        # Convert the value to a string, which is need for Bool
        # The json file should contain true or false, but due to being converted to a Python structure
        # this will be capitalized as True or False.
        if isinstance(value, bool):
            value = "{}".format(value).lower()

        if type_needed not in regex_patterns:
            raise Exception("Unknown type: {}".format(type_needed))

        regex = re.compile(regex_patterns[type_needed])
        if not regex.match(value):
            return False

    return True


def translate_documentation_types(str):
    """
    The docs use different type names, so this standardizes them.
    Example: The condition secretsmanager:RecoveryWindowInDays is listed as using a "Long"
    So return "Number"
    """

    if str in ["Arn", "ARN"]:
        return "Arn"
    elif str in ["Bool", "Boolean"]:
        return "Bool"
    elif str in ["Date"]:
        return "Date"
    elif str in ["Long", "Numeric"]:
        return "Number"
    elif str in ["String", "string", "ArrayOfString"]:
        return "String"
    elif str in ["Ip"]:
        return "Ip"
    else:
        raise Exception("Unknown data format: {}".format(str))


class Statement:
    findings = []
    resource_star = {}
    effect_allow = True
    stmt = None
    sid = None
    policy_id = None

    _is_valid = True

    def set_policy_identifier(self, policy_id):
        self.policy_id = policy_id

    def __init__(self, stmt, analyze=True):
        self.findings = []
        self.resource_star = {}
        self.stmt = stmt
        if analyze:
            if not self.analyze_statement():
                # Statement is malformed
                self._is_valid = False
                return

    def __str__(self):
        return json.dumps(self.stmt, indent=2)

    @property
    def is_valid(self):
        return self._is_valid

    def in_actions(self, privilege_prefix, privilege_name):
        """
        Given "s3" "GetObject", determine if the privilege is in this statement.
        This could happen either because the Action is ["s3:GetObject"] or ["s3:*", "ec2:*"]
        or because the action is not in the NotAction. For example, if we have an Allow on NotAction "ec2:*",
        then this, with "s3" "GetObject" returns True.
        """

        if "Action" in self.stmt:
            for action in make_list(self.stmt["Action"]):
                if action.value == "*" or action.value == "*:*":
                    return True

                expanded_actions = expand_action(action.value, raise_exceptions=False)

                for action_struct in expanded_actions:
                    if (
                        action_struct["service"] == privilege_prefix
                        and action_struct["action"] == privilege_name
                    ):
                        return True
            return False

        # Else, we're dealing with a NotAction
        for action in make_list(self.stmt["NotAction"]):
            if action == "*" or action == "*:*":
                # I don't think it makes sense to have a "NotAction" of "*", but I'm including this check anyway.
                return False

            for action_struct in expand_action(action.value, raise_exceptions=False):
                if (
                    action_struct["service"] == privilege_prefix
                    and action_struct["action"] == privilege_name
                ):
                    return False
        return True

    def get_resources_for_privilege(self, privilege_prefix, privilege_name):
        """
        If this privilege is allowed or denied by this statement, return the relevant resources.
        Else return None.

        For example, if the statement has Actions 's3:*', and resources
        ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"]
        and the privilege given is 's3:PutBucketPolicy' this should return ["arn:aws:s3:::bucket"],
        as the other resource is only applicable to object related privileges.
        
        If the privilege given is 's3:ListAllMyBuckets' this should return None, as that privilege does not
        apply to these resources.
        """

        if not self.in_actions(privilege_prefix, privilege_name):
            # Given privilege is unrelated to this statement
            return []

        if "NotResource" in self.stmt:
            # TODO How should I handle NotResource?
            return ["*"]

        affected_resources = []
        privilege_info = get_privilege_info(privilege_prefix, privilege_name)

        # Iterate through the resources defined in the action definition
        for resource_type in privilege_info["resource_types"]:
            resource_type = resource_type["resource_type"]

            # Only check the required resources which have a "*" at the end
            if "*" not in resource_type:
                continue

            arn_format = get_arn_format(
                resource_type, privilege_info["service_resources"]
            )

            # At least one resource has to match the action's required resources
            for resource in make_list(self.stmt["Resource"]):
                if is_arn_match(resource_type, arn_format, resource.value):
                    affected_resources.append(resource.value)
                elif resource.value == "*":
                    affected_resources.append(resource.value)

        # Ensure we match on "*"
        for resource in make_list(self.stmt["Resource"]):
            if resource.value == "*":
                affected_resources.append(resource.value)

        return affected_resources

    def add_finding(self, finding, detail=None, location={}):
        """
        Add finding to the class.

        finding: String specifiying the problem
        location: Dictionary with information about where this problem is. Often set to:
            {"location": "string"}
        """
        if "jsoncfg.config_classes.ConfigJSONObject" in str(type(location)):
            node_location = jsoncfg.node_location(location)
            location = {"line": node_location.line, "column": node_location.column}
        elif "jsoncfg.config_classes.ConfigJSONScalar" in str(type(location)):
            node_location = jsoncfg.node_location(location)
            location = {"string": location.value}
            location["line"] = node_location.line
            location["column"] = node_location.column
        elif "tuple" in str(type(location)):
            node_location = jsoncfg.node_location(location[1])
            location = {"string": location[0]}
            location["line"] = node_location.line
            location["column"] = node_location.column
        elif "jsoncfg.config_classes.ConfigJSONScalar" in str(
            type(location.get("string", ""))
        ):
            node_location = jsoncfg.node_location(location["string"])
            location["line"] = node_location.line
            location["column"] = node_location.column
            location["string"] = location["string"].value
        elif "tuple" in str(type(location.get("string", ""))):
            node_location = jsoncfg.node_location(location["string"][1])
            location["line"] = node_location.line
            location["column"] = node_location.column
            location["string"] = location["string"][0]

        elif "jsoncfg.config_classes" in str(type(location.get("string", ""))):
            location["string"] = location["string"][0]

        self.findings.append(Finding(finding, detail, location))

    def _check_principal(self, principal_element):
        """
        Checks that the Principal (or NotPrincipal) element conforms to expectations
        """

        for principal in make_list(principal_element):
            if jsoncfg.node_is_scalar(principal):
                if principal.value == "*":
                    continue
                else:
                    self.add_finding("UNKNOWN_PRINCIPAL", location=principal)
                    continue

            # We have a ConfigJSONObject
            for json_object in principal:
                key = json_object[0]
                if key == "AWS":
                    for aws_principal in make_list(json_object[1]):
                        text = aws_principal.value
                        account_id_regex = re.compile("^\d{12}$")
                        arn_regex = re.compile("^arn:[-a-z\*]*:iam::(\d{12}|):.*$")

                        if text == "*":
                            pass
                        elif account_id_regex.match(text):
                            pass
                        elif arn_regex.match(text):
                            pass
                        else:
                            self.add_finding(
                                "UNKNOWN_PRINCIPAL", location=principal, detail=text
                            )
                elif key == "Federated":
                    for federation in make_list(json_object[1]):
                        federation = federation.value
                        saml_regex = re.compile(
                            "^arn:[-a-z\*]*:iam::\d{12}:saml-provider/.*$"
                        )
                        if federation in [
                            "cognito-identity.amazonaws.com",
                            "www.amazon.com",
                            "graph.facebook.com",
                            "accounts.google.com",
                        ]:
                            pass
                        elif saml_regex.match(federation):
                            pass
                        else:
                            self.add_finding(
                                "UNKNOWN_FEDERATION_SOURCE",
                                location=principal,
                                detail=federation,
                            )
                elif key == "Service":
                    # This should be something like apigateway.amazonaws.com
                    # I don't know what all the restrictions could be though.
                    pass
                else:
                    self.add_finding("UNKNOWN_PRINCIPAL", location=principal)
        return True

    def _check_condition(self, operator, condition_block, expanded_actions):
        """
        operator is something like "StringLike"
        condition_block is something like {"s3:prefix":["home/${aws:username}/*"]}
        """

        operator_type_requirement = None
        for documented_operator in OPERATORS:
            op = documented_operator.lower()
            if operator.lower() in [
                op,
                op + "ifexists",
                "forallvalues:" + op,
                "foranyvalue:" + op,
                "forallvalues:" + op + "ifexists",
                "foranyvalue:" + op + "ifexists",
            ]:
                operator_type_requirement = OPERATORS[documented_operator]
                break

        if operator_type_requirement is None:
            self.add_finding(
                "UNKNOWN_OPERATOR",
                detail=operator,
                location=condition_block,
            )

        if operator_type_requirement == "Bool":
            # Get the value that is being compared against
            for c in condition_block:
                value = str(c[1].value).lower()
                if value != "true" and value != "false":
                    self.add_finding(
                        "MISMATCHED_TYPE_OPERATION_TO_NULL", location=condition_block
                    )
                    return False

        for block in condition_block:
            key = block[0]
            values = []
            for v in make_list(block[1]):
                values.append(v.value)

            # Check for known bad pattern
            if operator.lower() == "bool":
                if key.lower() == "aws:MultiFactorAuthPresent".lower() and "false" in values:
                    self.add_finding(
                        "BAD_PATTERN_FOR_MFA",
                        detail='The condition {"Bool": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent may not exist so it does not enforce MFA. You likely want to use a Deny with BoolIfExists.',
                        location=condition_block,
                    )
            elif operator.lower() == "null":
                if key.lower == "aws:MultiFactorAuthPresent".lower() and "false" in values:
                    self.add_finding(
                        "BAD_PATTERN_FOR_MFA",
                        detail='The condition {"Null": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent it does not enforce MFA, and only checks if the value exists. You likely want to use an Allow with {"Bool": {"aws:MultiFactorAuthPresent":"true"}}.',
                        location=condition_block,
                    )

            if operator.lower() in ["null"]:
                # The following condition is valid:
                # "Condition": { "Null": { "aws:MultiFactorAuthAge": true }
                # If we check further we'll get a MISMATCHED_TYPE finding due to
                # aws:MultiFactorAuthAge being checked against a bool value instead of a date
                continue

            # The key here from the example is "s3:prefix"
            condition_type = get_global_key_type(key)
            if condition_type:
                # This is a global key, like aws:CurrentTime
                # Check if the values match the type (ex. must all be Date values)
                if not is_value_in_correct_format_for_type(
                    condition_type, values
                ):
                    self.add_finding(
                        "MISMATCHED_TYPE",
                        detail="Type mismatch: {} requires a value of type {} but given {}".format(
                            key, condition_type, values
                        ),
                        location=condition_block,
                    )
            else:
                # See if this is a service specific key
                for action_struct in expanded_actions:
                    privilege_info = get_privilege_info(
                        action_struct["service"], action_struct["action"]
                    )

                    # Ensure the condition_key exists
                    match = None
                    for resource_type in privilege_info["resource_types"]:
                        for condition_key in resource_type["condition_keys"]:
                            if is_condition_key_match(condition_key, key):
                                match = condition_key

                    if match is None:
                        self.add_finding(
                            "UNKNOWN_CONDITION_FOR_ACTION",
                            detail="Unknown condition {} for action {}:{}".format(
                                key, action_struct["service"], action_struct["action"]
                            ),
                            location=condition_block,
                        )
                        continue

                    condition_type = None
                    for condition in privilege_info["service_conditions"]:
                        if condition["condition"] == match:
                            condition_type = condition["type"]

                    if condition_type is None:
                        raise Exception(
                            "Action condition not found in service definition for {}".format(
                                match
                            )
                        )

                    if not is_value_in_correct_format_for_type(
                        condition_type, values
                    ):
                        self.add_finding(
                            "MISMATCHED_TYPE",
                            detail="Type mismatch: {} requires a value of type {} but given {}".format(
                                key, condition_type, values
                            ),
                            location=condition_block,
                        )

                if condition_type is not None:
                    # if operator_type_requirement.lower() == 'string' and condition_type.lower() = 'arn':
                    #     # Ignore these.
                    #     pass
                    documenation_condition_type = translate_documentation_types(
                        condition_type
                    )
                    if operator_type_requirement != documenation_condition_type:
                        if (
                            operator_type_requirement == "String"
                            and documenation_condition_type == "Arn"
                        ):
                            self.add_finding(
                                "MISMATCHED_TYPE_BUT_USABLE",
                                detail="Type mismatch: {} requires a value of type {} but given {}".format(
                                    operator,
                                    operator_type_requirement,
                                    translate_documentation_types(condition_type),
                                ),
                                location=condition_block,
                            )
                        else:
                            self.add_finding(
                                "MISMATCHED_TYPE",
                                detail="Type mismatch: {} requires a value of type {} but given {}".format(
                                    operator,
                                    operator_type_requirement,
                                    translate_documentation_types(condition_type),
                                ),
                                location=condition_block,
                            )

        return

    def analyze_statement(self):
        """
        Given a statement, look for problems and extract out the parts.

        If it is malformed, return False
        """
        actions = []
        resources = []
        conditions = []

        # Check no unknown elements exist
        for element in self.stmt:
            if element[0] not in [
                "Effect",
                "Sid",
                "Principal",
                "NotPrincipal",
                "Action",
                "NotAction",
                "Resource",
                "NotResource",
                "Condition",
            ]:
                self.add_finding(
                    "MALFORMED",
                    detail="Statement contains an unknown element",
                    location=element,
                )
                return False

        # Track Sid for better location reporting
        if "Sid" in self.stmt:
            self.sid = self.stmt["Sid"].value

        # Check Principal if it exists. This only applicable to resource policies. Also applicable to
        # IAM role trust policies, but those don't have Resource elements, so that would break other things
        # if we tried to check those.
        if "Principal" in self.stmt and "NotPrincipal" in self.stmt:
            self.add_finding(
                "MALFORMED",
                detail="Statement contains both Principal and NotPrincipal",
                location=self.stmt,
            )
            return False

        if "Principal" in self.stmt:
            self._check_principal(self.stmt["Principal"])
        elif "NotPrincipal" in self.stmt:
            self._check_principal(self.stmt["NotPrincipal"])

        # Check Effect
        if "Effect" not in self.stmt:
            self.add_finding(
                "MALFORMED",
                detail="Statement does not contain an Effect element",
                location=self.stmt,
            )
            return False
        effect = self.stmt["Effect"]

        if effect.value not in ["Allow", "Deny"]:
            self.add_finding(
                "MALFORMED",
                detail="Unknown Effect used. Effect must be either Allow or Deny",
                location=effect,
            )
            return False

        if effect.value == "Allow":
            self.effect_allow = True
        else:
            self.effect_allow = False

        # Check Sid
        if "Sid" in self.stmt and not re.fullmatch(
            "[0-9A-Za-z]*", self.stmt["Sid"].value
        ):
            # The grammar is defined at https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
            self.add_finding("INVALID_SID", location={"string": self.stmt["Sid"]})
            return False

        # Check Action
        if "Action" in self.stmt and "NotAction" in self.stmt:
            self.add_finding(
                "MALFORMED",
                detail="Statement contains both Action and NotAction",
                location=self.stmt,
            )
            return False

        if "Action" in self.stmt:
            actions = make_list(self.stmt["Action"])
        elif "NotAction" in self.stmt:
            actions = make_list(self.stmt["NotAction"])
        else:
            self.add_finding(
                "MALFORMED",
                detail="Statement contains neither Action nor NotAction",
                location=self.stmt,
            )
            return False

        # Check Resource exists and save the list of resources for later
        if "Resource" in self.stmt and "NotResource" in self.stmt:
            self.add_finding(
                "MALFORMED",
                detail="Statement contains both Resource and NotResource",
                location=self.stmt,
            )
            return False

        if "Resource" in self.stmt:
            resources = make_list(self.stmt["Resource"])
        elif "NotResource" in self.stmt:
            resources = make_list(self.stmt["NotResource"])
        else:
            self.add_finding(
                "MALFORMED",
                detail="Statement contains neither Resource nor NotResource",
                location=self.stmt,
            )
            return False

        # Check if a Condition element exists and if so save them for later
        if "Condition" in self.stmt:
            conditions = make_list(self.stmt["Condition"])
            if len(conditions) > 1:
                self.add_finding(
                    "MALFORMED",
                    detail="Condition formatted incorrectly",
                    location=self.stmt,
                )
                return False

        # Expand the actions from s3:Get* to s3:GetObject and others
        expanded_actions = []
        has_malformed_action = False
        for action in actions:

            # Handle special case where all actions are allowed
            if action.value == "*" or action.value == "*:*":
                # TODO Should ensure the resource is "*" with this action
                continue

            try:
                # Given an action such as "s3:List*", return all the possible values it could have
                expanded_actions.extend(expand_action(action.value))
            except UnknownActionException as e:
                self.add_finding(
                    "UNKNOWN_ACTION",
                    detail=str(e),
                    location=action,
                )
                has_malformed_action = True
                continue
            except UnknownPrefixException as e:
                self.add_finding("UNKNOWN_PREFIX", detail=str(e), location=action)
                has_malformed_action = True
                continue
            except Exception as e:
                self.add_finding("EXCEPTION", detail=str(e), location=action)
                return False

        if has_malformed_action:
            return False

        # Check the resources are correct formatted correctly
        has_malformed_resource = False
        for resource in resources:
            if resource.value == "*":
                continue
            try:
                parts = resource.value.split(":")
            except AttributeError:
                has_malformed_resource = True
                self.add_finding(
                    "INVALID_ARN",
                    detail=(
                        "Must be a string. Maybe you're trying to analyze a "
                        "CloudFormation template which is outside of Parliament's "
                        "scope."
                    ),
                    location=resource,
                )
                continue
            if len(parts) < 6:
                has_malformed_resource = True
                self.add_finding(
                    "INVALID_ARN", detail="Does not have 6 parts", location=resource,
                )
                continue
            elif parts[0] != "arn":
                has_malformed_resource = True
                self.add_finding(
                    "INVALID_ARN", detail="Does not start with arn:", location=resource,
                )
                continue
            elif parts[1] not in ["aws", "aws-cn", "aws-us-gov", "aws-iso", "*", ""]:
                has_malformed_resource = True
                self.add_finding(
                    "INVALID_ARN", detail="Unexpected partition", location=resource,
                )
                continue

            # The service is in parts[2]

            elif not is_valid_region(parts[3]):
                has_malformed_resource = True
                self.add_finding(
                    "INVALID_ARN",
                    detail="Region expected to be of form like us-east-1",
                    location=resource,
                )
            elif not is_valid_account_id(parts[4]):
                has_malformed_resource = True
                self.add_finding(
                    "INVALID_ARN",
                    detail="Account expected to be of form like 123456789012",
                    location=resource,
                )
            # TODO I should check for the use of valid variables in the resource, such as ${aws:username}
            # See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
            # TODO Note, there are also service specific variables, such s3:prefix and sns:Endpoint
            # These are case-insensitive

        # Before checking the resource more, ensure we don't have malformed resources.
        # Also, looking for mismatches of Actions and Resources has different rules when a
        # Deny is involved.  For example, AWSEC2SpotServiceRolePolicy has a Deny on ec2:RunInstances
        # but only lists a resource of  "arn:aws:ec2:*:*:instance/*" instead of all the required
        # resources.
        # https://github.com/SummitRoute/aws_managed_policies/blob/4b71905a9042e66b22bc3d2b9cb1378b1e1d239e/policies/AWSEC2SpotServiceRolePolicy#L21

        if not has_malformed_resource and self.effect_allow:
            actions_without_matching_resources = []
            # Ensure the required resources for each action exist
            # Iterate through each action
            for action_struct in expanded_actions:
                privilege_info = get_privilege_info(
                    action_struct["service"], action_struct["action"]
                )

                # If the privilege requires a resource of "*", ensure it has it.
                if len(privilege_info["resource_types"]) == 0 or (
                    len(privilege_info["resource_types"]) == 1
                    and privilege_info["resource_types"][0]["resource_type"] == ""
                ):
                    match_found = False
                    for resource in resources:
                        if resource.value == "*":
                            match_found = True
                    if not match_found:
                        actions_without_matching_resources.append(
                            {
                                "action": "{}:{}".format(
                                    action_struct["service"], action_struct["action"]
                                ),
                                "required_format": "*",
                            }
                        )

                # Iterate through the resources defined in the action definition
                for resource_type in privilege_info["resource_types"]:
                    resource_type = resource_type["resource_type"]

                    # Only check the required resources which have a "*" at the end
                    if "*" not in resource_type:
                        continue

                    arn_format = get_arn_format(
                        resource_type, privilege_info["service_resources"]
                    )

                    # At least one resource has to match the action's required resources
                    match_found = False
                    for resource in resources:
                        if resource.value == "*":
                            # expansion leads to duplication actions
                            action_key = "{}:{}".format(
                                action_struct["service"], action_struct["action"]
                            )
                            self.resource_star.setdefault(action_key, 0)
                            self.resource_star[action_key] += 1
                            match_found = True
                            continue
                        if is_arn_match(resource_type, arn_format, resource.value):
                            match_found = True
                            continue

                    if not match_found:
                        actions_without_matching_resources.append(
                            {
                                "action": "{}:{}".format(
                                    action_struct["service"], action_struct["action"]
                                ),
                                "required_format": arn_format,
                            }
                        )
            if actions_without_matching_resources:
                # We have location info for each action via the variable `actions` which is a ConfigJSONArray, but
                # because we can only list one location, we'll just use the location of the statement
                # because `actions_without_matching_resources` contains the name of each action and the required format.
                self.add_finding(
                    "RESOURCE_MISMATCH",
                    detail=actions_without_matching_resources,
                    location=self.stmt
                )

        # If conditions exist, it will be an element, which was previously made into a list
        if len(conditions) == 1:
            # Iterate through each condition, of something like:
            # - "StringLike": {"s3:prefix":["home/${aws:username}/*"]}
            # - "DateGreaterThan" :{"aws:CurrentTime":"2019-07-16T12:00:00Z"}

            for condition in conditions[0]:
                # The operator is the first element (ex. `StringLike`) and the condition_block follows it
                operator = condition[0]
                condition_block = condition[1]
                self._check_condition(operator, condition_block, expanded_actions)

        # add the resource_star finding last
        # after all offending actions from the expanded list have been identified
        if self.resource_star:
            self.add_finding(
                "RESOURCE_STAR", detail=sorted(self.resource_star), location=self.stmt
            )

        return not has_malformed_resource
