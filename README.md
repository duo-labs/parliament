parliament is an AWS IAM linting library. It reviews policies looking for problems such as:
- malformed json
- missing required elements
- incorrect prefix and action names
- incorrect resources or conditions for the actions provided
- type mismatches
- bad policy patterns

This library duplicates (and adds to!) much of the functionality in the web console page when reviewing IAM policies in the browser.  We wanted that functionality as a library.

[demo](https://parliament.summitroute.com/)

# Installation
```
pip install parliament
```

# Usage
```
cat > test.json << EOF
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action":["s3:GetObject"],
        "Resource": ["arn:aws:s3:::bucket1"]
    }
}
EOF

parliament --file test.json
```

This will output:
```
MEDIUM - No resources match for the given action -  - [{'action': 's3:GetObject', 'required_format': 'arn:*:s3:::*/*'}] - {'actions': ['s3:GetObject'], 'filepath': 'test.json'}
```

This example is showing that the action s3:GetObject requires a resource matching an object path (ie. it must have a "/" in it).

The different input types allowed include:
- --file: Filename
- --directory: A directory path, for exmaple: `--directory . --include_policy_extension json --exclude_pattern ".*venv.*"`
- --aws-managed-policies: For use specifically with the repo https://github.com/z0ph/aws_managed_policies
- --auth-details-file: For use with the file returned by "aws iam get-account-authorization-details"
- --string: Provide a string such as '{"Version": "2012-10-17","Statement": {"Effect": "Allow","Action": ["s3:GetObject", "s3:PutBucketPolicy"],"Resource": ["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket2/*"]}}'

## Using parliament as a library
Parliament was meant to be used a library in other projects. A basic example follows.

```
from parliament import analyze_policy_string

analyzed_policy = analyze_policy_string(policy_doc)
for f in analyzed_policy.findings:
  print(f)
```

## Custom config file
You may decide you want to change the severity of a finding, the text associated with it, or that you want to ignore certain types of findings.  To support this, you can provide an override config file.  First, create a test.json file:

```
{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:abc",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": ["s3:*", "ec2:*"],
        "Resource": "arn:aws:s3:::test/*"
      }
    ]
 }
```

This will have two findings:
- LOW - Unknown action -  - Unknown action s3:abc
- MEDIUM - No resources match for the given action

The second finding will be very long, because every s3 and ec2 action are expanded and most are incorrect for the S3 object path resource that is provided.

Now create a file `config_override.yaml` with the following contents:

```
UNKNOWN_ACTION:
  severity: MEDIUM
  ignore_locations:
  - filepath:
    - testa.json
    - .*.py

RESOURCE_MISMATCH:
  ignore_locations:
  - actions: ".*s3.*"
```

Now run: `parliament --file test.json --config config_override.yaml`
You will have only one output: `MEDIUM - Unknown action -  - Unknown action s3:abc`

Notice that the severity of that finding has been changed from a `LOW` to a `MEDIUM`.  Also, note that the other finding is gone, because the previous `RESOURCE_MISMATCH` finding contained an `actions` element of `["s3:*", "ec2:*"]`.  The ignore logic converts the value you provide, and the finding value to lowercase,
and then uses your string as a regex.  This means that we are checking if `s3` is in `str(["s3:*", "ec2:*"])`

Now rename `test.json` to `testa.json` and rerun the command.  You will no longer have any output, because we are filtering based on the filepath for `UNKNOWN_ACTION` and filtering for any filepaths that contain `testa.json` or `.py`.

You can also check the exit status with `echo $?` and see the exit status is 0 when there are no findings. The exit status will be non-zero when there are findings.

You can have multiple elements in `ignore_locations`.  For example,
```
- filepath: "test.json"
  action: "s3:GetObject"
  resource: 
  - "a"
  - "b"
- resource: "c.*"
```

Assuming the finding has these types of values in the `location` element, this will ignore any finding that matches the filepath to "test.json" AND action to "s3:GetObject" AND the resource to "a" OR "b".  It will also ignore a resource that matches "c.*".

# Custom auditors

## Private Auditors
This section will show how to create your own private auditor to look for any policies that grant access to either of the sensitive buckets `secretbucket` and `othersecretbucket`.

Create a file `test.json` with contents:
```
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::secretbucket/*"
    }
}
```
This is an example of the policy we want to alert on. That policy will normally not generate any findings.

Create the file `config_override.yaml` with contents:

```
SENSITIVE_BUCKET_ACCESS:
  title: Sensitive bucket access
  description: Allows read access to an important S3 bucket
  severity: MEDIUM
  group: CUSTOM
```

In the `parliament` directory (that contains iam_definition.json), create the directory `private_auditors` and the file `parliament/private_auditors/sensitive_bucket_access.py`


```
from parliament import is_arn_match, expand_action

def audit(policy):
    action_resources = {}
    for action in expand_action("s3:*"):
        # Iterates through a list of containing elements such as
        # {'service': 's3', 'action': 'GetObject'}
        action_name = "{}:{}".format(action["service"], action["action"])
        action_resources[action_name] = policy.get_allowed_resources(action["service"], action["action"])
    
    for action_name in action_resources:
        resources = action_resources[action_name]
        for r in resources:
            if is_arn_match("object", "arn:aws:s3:::secretbucket*", r) or is_arn_match("object", "arn:aws:s3:::othersecretbucket*", r):
                policy.add_finding("SENSITIVE_BUCKET_ACCESS", location={"action": action_name, "resource": r})
```

This will look for any s3 access to the buckets of interest, including not only object access such as `s3:GetObject` access, but also things like `s3:PutBucketAcl`.

Running against our test file, we'll get the following output:
```
./bin/parliament --file test.json --config config_override.yaml --json

{"issue": "SENSITIVE_BUCKET_ACCESS", "title": "Sensitive bucket access", "severity": "MEDIUM", "description": "Allows read access to an important S3 bucket", "detail": "", "location": {"action": "s3:GetObject", "resource": "arn:aws:s3:::secretbucket/*", "filepath": "test.json"}}
```

You can now decide if this specific situation is ok for you, and choose to ignore it by modifying the
`config_override.yaml` to include:

```
ignore_locations:
  - filepath: "test.json"
    action: "s3:GetObject"
    resource: "arn:aws:s3:::secretbucket/\\*"
```

Notice that I had to double-escape the escape asterisk.  If another policy is created, say in test2.json that you'd like to ignore, you can just append those values to the list:

```
ignore_locations:
  - filepath: "test.json"
    action: "s3:GetObject"
    resource: "arn:aws:s3:::secretbucket/\\*"
  - filepath: "test2.json"
    action: "s3:GetObject"
    resource: "arn:aws:s3:::secretbucket/\\*"
```

Or you could do:

```
ignore_locations:
  - filepath:
    - "test.json"
    - "test2.json"
    action: "s3:GetObject"
    resource: "arn:aws:s3:::secretbucket/\\*"
```

## Unit tests for private auditors

To create unit tests for our new private auditor, create the directory `./parliament/private_auditors/tests/` and create the file `test_sensitive_bucket_access.py` there with the contents:

```
import unittest
from nose.tools import raises, assert_equal

# import parliament
from parliament import analyze_policy_string

class TestCustom(unittest.TestCase):
    """Test class for custom auditor"""

    def test_my_auditor(self):
        policy = analyze_policy_string(
            """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::secretbucket/*"}}""",
        )
        assert_equal(len(policy.findings), 1)
```

That test ensures that for the given policy (which is granting read access to our secret bucket) one finding will be created.

Now when you run `./tests/scripts/unit_tests.sh` there should be one additional test run.


## Community auditors

* The process for community auditors is the same as private auditors, except that:
 - The community auditors are located in the `parliament/community_auditors` folder instead of the `parliament/private_auditors`
 - The community auditors are bundled with the package and users can include them in their testing by specifying `--include-community-auditors` flag.

# Development
Setup a testing environment
```
python3 -m venv ./venv && source venv/bin/activate
pip3 install -r requirements.txt
```

Run unit tests with:
```
make test
```

Run locally as:
```
bin/parliament
```

## Updating the privilege info
The IAM data is obtained from scraping the docs [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html) and parsing this information with beautifulsoup using `./utils/update_iam_data.py`.

# Projects that use Parliament
- [CloudMapper](https://github.com/duo-labs/cloudmapper): Has functionality to audit AWS environments and will audit the IAM policies as part of that.
- [tf-parliament](https://github.com/rdkls/tf-parliament): Runs Parliament against terraform files
- [iam-lint](https://github.com/xen0l/iam-lint): Github action for linting AWS IAM policy documents 
- [Paco](https://paco-cloud.io): Cloud orchestration tool that integrates Parliament as a library to verify a project's IAM Policies and warns about findings.
