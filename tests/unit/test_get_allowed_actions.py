import unittest

from parliament import analyze_policy_string


class TestGetAllowedActions(unittest.TestCase):
    """Test class for get_allowed_actions"""

    def test_allowed_actions_simple(self):
        """test_allowed_actions_simple: Get a list of actions allowed by an IAM policy."""
        policy = analyze_policy_string(
            """{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":["cloud9:update*"],
      "Resource":["*"]
    }
  ]
}"""
        )
        allowed_actions = policy.get_allowed_actions()
        self.maxDiff = None
        desired_result = ['cloud9:updateenvironment', 'cloud9:updateenvironmentmembership', 'cloud9:updateusersettings']
        self.assertListEqual(allowed_actions, desired_result)
