from parliament import analyze_policy_string


class TestCalledViaServices:
    """Test class for CalledVia service validation auditor"""

    def test_valid_calledvia_service(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "kms:Decrypt",
              "Resource": "*",
              "Condition": {
                "ForAnyValue:StringEquals": {
                  "aws:CalledVia": ["cloudformation.amazonaws.com"]
                }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" not in policy.finding_ids

    def test_invalid_calledvia_service(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "kms:Decrypt",
              "Resource": "*",
              "Condition": {
                "ForAnyValue:StringEquals": {
                  "aws:CalledVia": ["s3.amazonaws.com"]
                }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" in policy.finding_ids

    def test_valid_calledviafirst(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "kms:Decrypt",
              "Resource": "*",
              "Condition": {
                "StringEquals": {
                  "aws:CalledViaFirst": "athena.amazonaws.com"
                }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" not in policy.finding_ids

    def test_invalid_calledvialast(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "kms:Decrypt",
              "Resource": "*",
              "Condition": {
                "StringEquals": {
                  "aws:CalledViaLast": "ec2.amazonaws.com"
                }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" in policy.finding_ids

    def test_multiple_services_mixed_valid_invalid(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "kms:Decrypt",
              "Resource": "*",
              "Condition": {
                "ForAnyValue:StringEquals": {
                  "aws:CalledVia": [
                    "dynamodb.amazonaws.com",
                    "lambda.amazonaws.com"
                  ]
                }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" in policy.finding_ids

    def test_all_supported_services(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "kms:Decrypt",
              "Resource": "*",
              "Condition": {
                "ForAnyValue:StringEquals": {
                  "aws:CalledVia": [
                    "athena.amazonaws.com",
                    "cloudformation.amazonaws.com",
                    "dynamodb.amazonaws.com",
                    "kms.amazonaws.com",
                    "ram.amazonaws.com",
                    "rolesanywhere.amazonaws.com"
                  ]
                }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" not in policy.finding_ids

    def test_no_condition_no_finding(self):
        policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::mybucket/*"
            }
          ]
        }
        """
        policy = analyze_policy_string(
            policy_string, include_community_auditors=True
        )
        assert "INVALID_CALLEDVIA_SERVICE" not in policy.finding_ids
