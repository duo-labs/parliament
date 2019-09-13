parliament is an AWS IAM linting library. It reviews policies looking for problems such as:
- malformed json
- missing required elements
- incorrect prefix and action names
- incorrect resources or conditions for the actions provided
- type mismatches
- bad policy patterns

This library duplicates (and adds to!) much of the functionality in the web console page when reviewing IAM policies in the browser.  We wanted that functionality as a library.

The IAM data is obtained from scraping the docs [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html) and parsing this information with beautifulsoup using `./utils/update_iam_data.py`.

# Installation
```
pip install parliament
```

# Usage
```
from parliament.policy import analyze_policy_string

str = """{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:BAD",
        "Resource": "*"
    }
}
"""

policy = analyze_policy_string(str)
if len(policy.findings) > 0:
    for finding in policy.findings:
        print("{} - {} - {}".format(finding.severity_name(), finding.issue, finding.location))
```

This prints:
```
INVALID - Unknown action s3:BAD - {'string': {'Effect': 'Allow', 'Action': 's3:BAD', 'Resource': '*'}}
```

See `./utils/lint.py` for further examples.