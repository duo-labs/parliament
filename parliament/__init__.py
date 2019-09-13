"""
This library is a linter for AWS IAM policies.
"""
__version__ = "0.2.0"

import os
import json

# On initialization, load the IAM data
iam_definition_path = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "iam_definition.json"
)
iam_definition = json.load(open(iam_definition_path, "r"))
