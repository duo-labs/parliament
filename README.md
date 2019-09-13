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
$ parliament --string '{"Version":"2012-10-17","Statement": {"Effect": "Allow","Action":["s3:GetObject"],"Resource": ["arn:aws:s3:::bucket1"]}}'
INVALID - No resources match for s3:GetObject which requires a resource format of arn:*:s3:::*/* for the resource object* - {'filepath': None}
```

This example is showing that a resource specifying an S3 bucket (not an object path) was given in a policy with s3:GetObject, which requires an object path. 

See `./bin/parliament.py` for further examples.
