import unittest
from nose.tools import raises, assert_equal, assert_true, assert_false

import parliament


class TestPrivilegData(unittest.TestCase):
    """Test class for the parliament/iam_definition.json file"""

    def test_minimum_number_of_services(self):
        assert_true(
            len(parliament.iam_definition) > 220,
            "There should be over 220 services in the definition file",
        )

    def test_contains_all_elements(self):
        # Find the ec2 service
        ec2_service = None
        for service in parliament.iam_definition:
            if service["prefix"] == "ec2":
                ec2_service = service
                break
        assert_true(ec2_service is not None)

        assert_equal(ec2_service["service_name"], "Amazon EC2")
        assert_true(
            len(ec2_service["resources"]) > 30,
            "There should be over 30 resources in the EC2 service",
        )

        vpc_resource = None
        for resource in ec2_service["resources"]:
            if resource["resource"] == "vpc":
                vpc_resource = resource
                break
        assert_true(vpc_resource is not None)

        assert_true(
            "vpc" in vpc_resource["arn"],
            "The arn for the vpc resource should contain the string 'vpc'",
        )
        assert_true(
            len(vpc_resource["condition_keys"]) >= 5,
            "There should be at least 5 condition_keys in the vpc resource",
        )
        assert_true(len(ec2_service["resources"]) >= 32)

        vpc_condition = None
        for condition in ec2_service["conditions"]:
            if condition["condition"] == "ec2:Vpc":
                vpc_condition = condition
                break
        assert_true(vpc_condition is not None)

        assert_true(vpc_condition["type"] == "ARN")
        assert_true(len(ec2_service["conditions"]) >= 59)

        assert_true(len(ec2_service["privileges"]) >= 363)
