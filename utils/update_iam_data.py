#!/usr/bin/env python

from os import listdir
from os.path import isfile, join
import re
import json

from bs4 import BeautifulSoup

"""
Setup
-----

# Install libraries
pip install beautifulsoup4

# Download files
wget -r -np -k -A .html -nc https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html
"""


def chomp(string):
    """This chomp cleans up all white-space, not just at the ends"""
    string = str(string)
    response = string.replace("\n", " ")  # Convert line ends to spaces
    response = re.sub(
        " [ ]*", " ", response
    )  # Truncate multiple spaces to single space
    response = re.sub("^[ ]*", "", response)  # Clean start
    return re.sub("[ ]*$", "", response)  # Clean end


mypath = "./docs.aws.amazon.com/IAM/latest/UserGuide/"
schema = []

#for filename in ['list_amazoncloudwatchlogs.html']:
for filename in [f for f in listdir(mypath) if isfile(join(mypath, f))]:
    if not filename.startswith("list_"):
        continue

    with open(mypath + filename, "r") as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        main_content = soup.find(id="main-content")
        if main_content is None:
            continue

        # Get service name
        title = main_content.find("h1", class_="topictitle")
        title = re.sub(".*Actions, Resources, and Condition Keys for *", "", str(title))
        title = title.replace("</h1>", "")
        service_name = chomp(title)

        prefix = ""
        for c in main_content.find("h1", class_="topictitle").parent.children:
            if "prefix" in str(c):
                prefix = str(c)
                prefix = prefix.split('<code class="code">')[1]
                prefix = prefix.split("</code>")[0]
                break

        service_schema = {
            "service_name": service_name,
            "prefix": prefix,
            "privileges": [],
            "resources": [],
            "conditions": [],
        }

        tables = main_content.find_all("div", class_="table-contents")

        for table in tables:
            # There can be 3 tables, the actions table, an ARN table, and a condition key table
            # Example: https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awssecuritytokenservice.html
            if "<th>Actions</th>" not in [str(x) for x in table.find_all("th")]:
                continue

            rows = table.find_all("tr")
            row_number = 0
            while row_number < len(rows):
                row = rows[row_number]

                cells = row.find_all("td")
                if len(cells) == 0:
                    # Skip the header row, which has th, not td cells
                    row_number += 1
                    continue

                if len(cells) != 6:
                    # Sometimes the privilege might span multiple rows.
                    # Example: amazonroute53-DisassociateVPCFromHostedZone
                    # We should be handling this, but if we are not, then bail
                    raise Exception("Unexpected format in {}: {}".format(prefix, row))

                # See if this cell spans multiple rows
                rowspan = 1
                if "rowspan" in cells[0].attrs:
                    rowspan = int(cells[0].attrs["rowspan"])

                priv = ""
                # Get the privilege
                for link in cells[0].find_all("a"):
                    if "href" not in link.attrs:
                        # Skip the <a id='...'> tags
                        continue
                    priv = chomp(link.text)
                if priv == "":
                    priv = chomp(cells[0].text)

                description = chomp(cells[1].text)
                access_level = chomp(cells[2].text)

                resource_types = []
                resource_cell = 3

                while rowspan > 0:
                    if len(cells) == 3 or len(cells) == 6:
                        # ec2:RunInstances contains a few "scenarios" which start in the
                        # description field, len(cells) is 5.
                        # I'm ignoring these as I don't know how to handle them.
                        # These include things like "EC2-Classic-InstanceStore" and
                        # "EC2-VPC-InstanceStore-Subnet"

                        resource_type = chomp(cells[resource_cell].text)

                        condition_keys_element = cells[resource_cell + 1]
                        condition_keys = []
                        if condition_keys_element.text != "":
                            for key_element in condition_keys_element.find_all("p"):
                                condition_keys.append(chomp(key_element.text))

                        dependent_actions_element = cells[resource_cell + 2]
                        dependent_actions = []
                        if dependent_actions_element.text != "":
                            for action_element in dependent_actions_element.find_all(
                                "p"
                            ):
                                dependent_actions.append(chomp(action_element.text))
                        resource_types.append(
                            {
                                "resource_type": resource_type,
                                "condition_keys": condition_keys,
                                "dependent_actions": dependent_actions,
                            }
                        )
                    rowspan -= 1
                    if rowspan > 0:
                        row_number += 1
                        resource_cell = 0
                        row = rows[row_number]
                        cells = row.find_all("td")

                if "[permission only]" in priv:
                    priv = priv.split(" ")[0]

                privilege_schema = {
                    "privilege": priv,
                    "description": description,
                    "access_level": access_level,
                    "resource_types": resource_types,
                }

                service_schema["privileges"].append(privilege_schema)
                row_number += 1

        # Get resource table
        for table in tables:
            if "<th>Resource Types</th>" not in [str(x) for x in table.find_all("th")]:
                continue

            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all("td")

                if len(cells) == 0:
                    # Skip the header row, which has th, not td cells
                    continue

                if len(cells) != 3:
                    raise Exception(
                        "Unexpected number of resource cells {} in {}".format(
                            len(cells), filename
                        )
                    )

                resource = chomp(cells[0].text)

                arn = chomp(cells[1].text)
                conditions = []
                for condition in cells[2].find_all("p"):
                    conditions.append(chomp(condition.text))

                service_schema["resources"].append(
                    {"resource": resource, "arn": arn, "condition_keys": conditions}
                )

        # Get condition keys table
        for table in tables:
            if "<th>Condition Keys</th>" not in [
                str(x) for x in table.find_all("th")
            ] or "<th>Type</th>" not in [str(x) for x in table.find_all("th")]:
                continue

            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all("td")

                if len(cells) == 0:
                    # Skip the header row, which has th, not td cells
                    continue

                if len(cells) != 3:
                    raise Exception(
                        "Unexpected number of condition cells {} in {}".format(
                            len(cells), filename
                        )
                    )

                condition = chomp(cells[0].text)
                description = chomp(cells[1].text)
                value_type = chomp(cells[2].text)

                service_schema["conditions"].append(
                    {
                        "condition": condition,
                        "description": description,
                        "type": value_type,
                    }
                )
        schema.append(service_schema)

print(json.dumps(schema, indent=2, sort_keys=True))
