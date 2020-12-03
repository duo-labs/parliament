import importlib
import logging
import os
import pkgutil
import sys
import jsoncfg
from pathlib import Path

from . import expand_action
from .finding import Finding
from .misc import make_list
from .statement import Statement


class Policy:
    _findings = []
    policy_json = None
    version = None
    statements = []
    policy = None

    def __init__(self, policy_json, filepath=None, config=None):
        self._findings = []
        self.statements = []
        self.policy_json = policy_json
        self.filepath = filepath
        self.config = config if config else {}

    def add_finding(self, finding, detail="", location={}):
        if type(location) == tuple and "jsoncfg.config_classes" in str(
            type(location[1])
        ):
            location_data = {}
            location_data["string"] = location[0]
            location_data["lineno"] = jsoncfg.node_location(location[1])[0]
            location_data["column"] = jsoncfg.node_location(location[1])[1]
            location = location_data
        elif "ConfigJSONScalar" in str(type(location)):
            location_data = {}
            location_data["string"] = location.value
            location_data["lineno"] = jsoncfg.node_location(location).line
            location_data["column"] = jsoncfg.node_location(location).column
            location = location_data
        if "filepath" not in location:
            location["filepath"] = self.filepath
        self._findings.append(Finding(finding, detail, location))

    @property
    def findings(self):
        all_findings = []
        all_findings.extend(self._findings)

        for stmt in self.statements:
            for finding in stmt.findings:
                if "filepath" not in finding.location:
                    finding.location["filepath"] = self.filepath

                all_findings.append(finding)

        return all_findings

    @property
    def finding_ids(self):
        finding_ids = set()
        for finding in self.findings:
            finding_ids.add(finding.issue)
        return finding_ids

    @property
    def is_valid(self):
        for stmt in self.statements:
            if not stmt.is_valid:
                return False
        return True

    def get_references(self, privilege_prefix, privilege_name):
        """
        Identify all statements that reference this privilege,
        then return a dictionary where the keys are the resources referenced by the statements,
        and the values are a list of the statements
        """
        references = {}
        for stmt in self.statements:
            stmt_relevant_resources = stmt.get_resources_for_privilege(
                privilege_prefix, privilege_name
            )
            for resource in stmt_relevant_resources:
                references[resource] = references.get(resource, [])
                references[resource].append(stmt)
        return references

    def get_allowed_actions(self):
        actions_referenced = set()
        for stmt in self.statements:
            actions = make_list(stmt.stmt["Action"])
            for action in actions:
                expanded_actions = expand_action(action.value)
                for expanded_action in expanded_actions:
                    actions_referenced.add(
                        "{}:{}".format(
                            expanded_action["service"], expanded_action["action"]
                        )
                    )

        # actions_referenced is now a set like: {'lambda:UpdateFunctionCode', 'glue:UpdateDevEndpoint'}
        # We need to identify which of these are actually allowed though, as some of those could just be a deny
        # Worst case scenario though, we have a list of every action if someone included Action '*'

        allowed_actions = []
        for action in actions_referenced:
            parts = action.split(":")
            allowed_resources = self.get_allowed_resources(parts[0], parts[1])
            if len(allowed_resources) > 0:
                action = action.lower()
                allowed_actions.append(action)
        return allowed_actions

    def get_allowed_resources(self, privilege_prefix, privilege_name):
        """
        Given a privilege like s3:GetObject, identify all the resources (if any),
        this is allowed to be used with.

        Examples, assuming given "s3" "GetObject":
        - With a policy with s3:* on "*", this would return "*"
        - With a policy with s3:* on ["arn:aws:s3:::examplebucket", "arn:aws:s3:::examplebucket/*"],
          this would only return "arn:aws:s3:::examplebucket/*" because that is the only object resource.
        """

        def __is_allowed(stmts):
            """
            Given statements that are all relevant to the same resource and privilege,
            (meaning each statement must have an explicit allow or deny on the privilege) 
            determine if it is allowed, which means no Deny effects.
            """
            has_allow = False
            for stmt in stmts:
                if stmt.effect_allow:
                    has_allow = True
                else:
                    # If there is a Condition in the Deny, we don't count this as Deny'ing the action
                    # entirely so skip it
                    if "Condition" in stmt.stmt:
                        continue
                    return False
            return has_allow

        allowed_resources = []
        all_references = self.get_references(privilege_prefix, privilege_name)
        for resource in all_references:
            resource_is_allowed = __is_allowed(all_references[resource])

            # To avoid situations where we have an allow on a specific resource, but a deny
            # on *, I'm making a special case here
            # I should do regex intersections across each resource, but this will avoid
            # common situations for now
            if resource == "*" and not resource_is_allowed:
                # Only apply this case when the deny statement has no condition
                for stmt in all_references[resource]:
                    if not stmt.effect_allow and "Condition" not in stmt.stmt:
                        return []

            if resource_is_allowed:
                allowed_resources.append(resource)

        return allowed_resources

    def check_for_bad_patterns(self):
        """
        Look for privileges across multiple statements that result in problems such as privilege escalation.
        """

        def check_bucket_privesc(refs, bucket_privilege, object_privilege):
            # If the bucket privilege exists for a bucket, but not the object privilege for objects
            # in that bucket then the bucket privilege can be abused to get that object privilege
            for resource in refs[bucket_privilege]:
                if not (
                    resource in refs[object_privilege]
                    or resource + "/*" in refs[object_privilege]
                ):
                    self.add_finding(
                        "RESOURCE_POLICY_PRIVILEGE_ESCALATION",
                        detail="Possible resource policy privilege escalation on {} due to s3:{} not being allowed, but does allow s3:{}".format(
                            resource, object_privilege, bucket_privilege
                        ),
                    )

        # Get the resource references we'll be using
        refs = {}
        for priv in [
            "PutBucketPolicy",
            "PutBucketAcl",
            "PutLifecycleConfiguration",
            "PutObject",
            "GetObject",
            "DeleteObject",
        ]:
            refs[priv] = self.get_allowed_resources("s3", priv)

        # Check each bad combination.  If the bucket level privilege is allowed,
        # but not the object level privilege, then we likely have a privilege escalation issue.
        check_bucket_privesc(refs, "PutBucketPolicy", "PutObject")
        check_bucket_privesc(refs, "PutBucketPolicy", "GetObject")
        check_bucket_privesc(refs, "PutBucketPolicy", "DeleteObject")

        check_bucket_privesc(refs, "PutBucketAcl", "PutObject")
        check_bucket_privesc(refs, "PutBucketAcl", "GetObject")
        check_bucket_privesc(refs, "PutBucketAcl", "DeleteObject")

        check_bucket_privesc(refs, "PutLifecycleConfiguration", "DeleteObject")

    def analyze(
        self,
        ignore_private_auditors=False,
        private_auditors_custom_path=None,
        include_community_auditors=False,
    ):
        """
        Returns False if this policy is so broken that it couldn't be analyzed further.
        On True, it may still have findings.

        In either case, it will create Findings if there are any.
        """

        # Check no unknown elements exist
        element_strings = []
        for element in self.policy_json:
            element_strings.append(element[0])
            if element[0] not in ["Version", "Statement", "Id"]:
                self.add_finding(
                    "MALFORMED",
                    detail="Policy contains an unknown element",
                    location=element,
                )
                return False

        if "Statement" not in element_strings:
            self.add_finding(
                "MALFORMED",
                detail="Policy does not contain a required element Statement",
            )
            return False

        # Check Version
        if not jsoncfg.node_exists(self.policy_json["Version"]):
            self.add_finding("NO_VERSION")
        else:
            self.version = self.policy_json["Version"].value

            if self.version not in ["2012-10-17", "2008-10-17"]:
                self.add_finding(
                    "INVALID_VERSION", location=self.policy_json["Version"]
                )
            elif self.version != "2012-10-17":
                # TODO I should have a check so that if an older version is being used,
                # and a variable is detected, it should be marked as higher severity.
                self.add_finding("OLD_VERSION", location=self.policy_json["Version"])

        # Check Statements
        if not jsoncfg.node_exists(self.policy_json["Statement"]):
            self.add_finding(
                "MALFORMED", detail="Policy does not contain a Statement element"
            )
            return False

        sids = {}
        stmts_json = make_list(self.policy_json["Statement"])
        for stmt_json in stmts_json:
            stmt = Statement(stmt_json)
            self.statements.append(stmt)

            # Report duplicate Statement Ids
            if stmt.sid is not None:
                sid = stmt.sid
                sids.setdefault(sid, 0)
                sids[sid] += 1

                # Only report the finding once, when encountering the first duplicate
                if sids[sid] == 2:
                    self.add_finding(
                        "DUPLICATE_SID",
                        detail="Duplicate Statement Id '{}' in policy".format(sid),
                    )

        if not self.is_valid:
            # Do not continue. Further checks will not work with invalid statements.
            return False

        # Look for bad patterns
        self.check_for_bad_patterns()

        if not ignore_private_auditors:
            # Import any private auditing modules
            private_auditors_directory = "private_auditors"
            private_auditors_directory_path = (
                Path(os.path.abspath(__file__)).parent / private_auditors_directory
            )

            if private_auditors_custom_path is not None:
                private_auditors_directory_path = private_auditors_custom_path
                # Ensure we can import from this directory
                sys.path.append(".")

            private_auditors = {}
            for importer, name, _ in pkgutil.iter_modules(
                [private_auditors_directory_path]
            ):
                full_package_name = "parliament.%s.%s" % (
                    private_auditors_directory,
                    name,
                )

                if private_auditors_custom_path is not None:
                    path_with_dots = private_auditors_directory_path.replace(
                        "/", "."
                    ).replace("\\", ".")
                    full_package_name = path_with_dots + "." + name

                module = importlib.import_module(full_package_name)
                private_auditors[name] = module

            if len(private_auditors) == 0 and private_auditors_custom_path is not None:
                raise Exception(
                    "No private auditors found at {}".format(
                        private_auditors_custom_path
                    )
                )

            # Run them
            for m in private_auditors:
                logging.info(f"*** Checking with private auditor: {m}")
                private_auditors[m].audit(self)

        if include_community_auditors is True:
            # Import any private auditing modules
            community_auditors_directory = "community_auditors"
            community_auditors_directory_path = (
                Path(os.path.abspath(__file__)).parent / community_auditors_directory
            )

            community_auditors = {}
            for importer, name, _ in pkgutil.iter_modules(
                [community_auditors_directory_path]
            ):
                full_package_name = "parliament.%s.%s" % (
                    community_auditors_directory,
                    name,
                )

                path_with_dots = full_package_name.replace("/", ".")
                full_package_name = path_with_dots

                module = importlib.import_module(full_package_name)
                community_auditors[name] = module

            # Run them
            for m in community_auditors:
                logging.info(f"*** Checking with community auditor: {m}")
                try:
                    community_auditors[m].audit(self)
                except Exception as e:
                    self.add_finding(
                        "EXCEPTION", detail=str(e), location={"community_auditor": m}
                    )

        return True
