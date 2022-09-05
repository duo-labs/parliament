from parliament import analyze_policy_string


class TestResources:
    """Test class for principals"""

    def test_resource_with_sub(self):
        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"AddPerm",
      "Effect":"Allow",
      "Principal": "*",
      "Action":["ssm:PutParameter"],
      "Resource":[{"Fn::Sub": "arn:aws:ssm:*:${AWS::AccountId}:*"}]
    }
  ]
}"""
        )
        assert policy.finding_ids == {"INVALID_ARN"}
