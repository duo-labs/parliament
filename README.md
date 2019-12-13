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
    filepath:
      - testa.json
      - .py

RESOURCE_MISMATCH:
  ignore_locations:
    actions: "s3:*"
```

Now run: `parliament --file test.json --config config_override.yaml`
You will have only one output: `MEDIUM - Unknown action -  - Unknown action s3:abc`

Notice that the severity of that finding has been changed from a `LOW` to a `MEDIUM`.  Also, note that the other finding is gone, because the previous `RESOURCE_MISMATCH` finding contained an `actions` element of `["s3:*", "ec2:*"]`.  The ignore logic looks for any of the values you provide in the element within `location`.  This means that we are doing `if "s3:*" in str(["s3:*", "ec2:*"])`

Now rename `test.json` to `testa.json` and rerun the command.  You will no longer have any output, because we are filtering based on the filepath for `UNKNOWN_ACTION` and filtering for any filepaths that contain `testa.json` or `.py`.

You can also check the exit status with `echo $?` and see the exit status is 0 when there are no findings. The exit status will be non-zero when there are findings.




## Using parliament as a library
Parliament was meant to be used a library in other projects. A basic example follows.

```
from parliament import analyze_policy_string

analyzed_policy = analyze_policy_string(policy_doc)
for f in analyzed_policy.findings:
  print(f)
```


# Development
Setup a testing environment
```
python3 -m venv ./venv && source venv/bin/activate
pip install boto3 jmespath pyyaml nose coverage
```

Run unit tests with:
```
./tests/scripts/unit_tests.sh
```

Run locally as:
```
bin/parliament
```