#!/usr/bin/env python3

from os import listdir
from os.path import isfile, join
import re
import json
import requests
from pathlib import Path

from bs4 import BeautifulSoup

# Code for get_links_from_base_actions_resources_conditions_page and update_html_docs_directory borrowed from https://github.com/salesforce/policy_sentry/blob/1126f174f49050b95bddf7549aedaf11fa51a50b/policy_sentry/scraping/awsdocs.py#L31
BASE_DOCUMENTATION_URL = "https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"


def get_links_from_base_actions_resources_conditions_page():
    """Gets the links from the actions, resources, and conditions keys page, and returns their filenames."""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
    }
    html = requests.get(BASE_DOCUMENTATION_URL, headers=headers)
    soup = BeautifulSoup(html.content, "html.parser")
    html_filenames = []
    for i in soup.find("div", {"class": "highlights"}).findAll("a"):
        html_filenames.append(i["href"])
    return html_filenames


def update_html_docs_directory(html_docs_destination):
    """
    Updates the HTML docs from remote location to either (1) local directory
    (i.e., this repository, or (2) the config directory
    :return:
    """
    link_url_prefix = (
        "https://docs.aws.amazon.com/service-authorization/latest/reference/"
    )
    initial_html_filenames_list = (
        get_links_from_base_actions_resources_conditions_page()
    )
    # Remove the relative path so we can download it
    html_filenames = [sub.replace("./", "") for sub in initial_html_filenames_list]
    pos = 0
    
    for page in html_filenames:
        pos += 1
        print(f"Downloading {pos} of {len(html_filenames)} - {page}")

        response = requests.get(link_url_prefix + page, allow_redirects=False)
        # Replace the CSS stuff. Basically this:
        """
        <link href='href="https://docs.aws.amazon.com/images/favicon.ico"' rel="icon" type="image/ico"/>
        <link href='href="https://docs.aws.amazon.com/images/favicon.ico"' rel="shortcut icon" type="image/ico"/>
        <link href='href="https://docs.aws.amazon.com/font/css/font-awesome.min.css"' rel="stylesheet" type="text/css"/>
        <link href='href="https://docs.aws.amazon.com/css/code/light.css"' id="code-style" rel="stylesheet" type="text/css"/>
        <link href='href="https://docs.aws.amazon.com/css/awsdocs.css?v=20181221"' rel="stylesheet" type="text/css"/>
        <link href='href="https://docs.aws.amazon.com/assets/marketing/css/marketing-target.css"' rel="stylesheet" type="text/css"/>
        list_amazonkendra.html downloaded
        """
        soup = BeautifulSoup(response.content, "html.parser")
        for link in soup.find_all("link"):
            if link.get("href").startswith("/"):
                temp = link.attrs["href"]
                link.attrs["href"] = link.attrs["href"].replace(
                    temp, f"https://docs.aws.amazon.com{temp}"
                )

        for script in soup.find_all("script"):
            try:
                if "src" in script.attrs:
                    if script.get("src").startswith("/"):
                        temp = script.attrs["src"]
                        script.attrs["src"] = script.attrs["src"].replace(
                            temp, f"https://docs.aws.amazon.com{temp}"
                        )
            except TypeError as t_e:
                print(t_e)
                print(script)
            except AttributeError as a_e:
                print(a_e)
                print(script)

        with open(html_docs_destination + page, "w") as file:
            # file.write(str(soup.html))
            file.write(str(soup.prettify()))
            file.close()
        # print(f"{page} downloaded")


def chomp(string):
    """This chomp cleans up all white-space, not just at the ends"""
    string = str(string)
    response = string.replace("\n", " ")  # Convert line ends to spaces
    response = re.sub(
        " [ ]*", " ", response
    )  # Truncate multiple spaces to single space
    response = re.sub("^[ ]*", "", response)  # Clean start
    return re.sub("[ ]*$", "", response)  # Clean end


def no_white_space(string):
    string = str(string)
    response = string.replace("\n", "")  # Convert line ends to spaces
    response = re.sub("[ ]*", "", response)
    return response


COLUMN_HEADERS = {
    "action": "actions",
    "description": "description",
    "resource_type": "resource types",
    "condition_keys": "condition keys",
    "access_level": "access level",
    "dependent_actions": "dependent actions",
}


def column_indexes(table):
    """Resolve each known column to its position using the table's header text.

    AWS has changed both the order and the number of columns in the actions
    table over time, and no longer publishes a dependent-actions column at all,
    so a column that is absent resolves to None.
    """
    headers = [chomp(th.get_text(" ", strip=True)).lower() for th in table.find_all("th")]

    indexes = {}
    for key, needle in COLUMN_HEADERS.items():
        indexes[key] = next(
            (i for i, header in enumerate(headers) if needle in header), None
        )
    return indexes


def cell_text(cells, index):
    if index is None or index >= len(cells):
        return ""
    return chomp(cells[index].text)


def cell_paragraphs(cells, index):
    if index is None or index >= len(cells):
        return []
    element = cells[index]
    if element.text == "":
        return []
    return [chomp(p.text) for p in element.find_all("p")]


def header_matches(string, table):
    headers = [chomp(str(x)).lower() for x in table.find_all("th")]
    match_found = False
    for header in headers:
        if string in header:
            match_found = True
    if not match_found:
        return False
    return True


# Create the docs directory
DOCS_DIR = "docs"
print("Downloading html pages to:", DOCS_DIR)
Path(DOCS_DIR).mkdir(parents=True, exist_ok=True)
update_html_docs_directory(f"{DOCS_DIR}/")

mypath = f"./{DOCS_DIR}/"
schema = []

# for filename in ['list_amazons3.html']:
for filename in [f for f in listdir(mypath) if isfile(join(mypath, f))]:
    if not filename.startswith("list_"):
        continue

    with open(mypath + filename, "r") as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        main_content = soup.find(id="main-content")
        if main_content is None:
            continue

        # Get service name
        title = main_content.find("h1", class_="topictitle").text
        title = re.sub(".*Actions, resources, and condition keys for *", "", str(title))
        title = title.replace("</h1>", "")
        service_name = chomp(title)

        prefix = ""
        for c in main_content.find("h1", class_="topictitle").parent.children:
            if "prefix" in str(c):
                prefix = str(c)
                prefix = prefix.split('<code class="code">')[1]
                prefix = chomp(prefix.split("</code>")[0])
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
            if not header_matches("actions", table) or not header_matches(
                "description", table
            ):
                continue

            # Column order and count vary between service pages, so resolve each
            # column by its header text rather than by a fixed index.
            columns = column_indexes(table)
            column_count = len(table.find_all("th"))
            if columns["action"] is None or columns["resource_type"] is None:
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

                if len(cells) != column_count:
                    # Sometimes the privilege contains Scenarios, and I don't know how to handle this
                    break
                    # raise Exception("Unexpected format in {}: {}".format(prefix, row))

                # See if this cell spans multiple rows
                rowspan = 1
                if "rowspan" in cells[columns["action"]].attrs:
                    rowspan = int(cells[columns["action"]].attrs["rowspan"])

                priv = ""
                # Get the privilege
                for link in cells[columns["action"]].find_all("a"):
                    if "href" not in link.attrs:
                        # Skip the <a id='...'> tags
                        continue
                    priv = chomp(link.text)
                if priv == "":
                    priv = chomp(cells[columns["action"]].text)

                description = cell_text(cells, columns["description"])
                access_level = cell_text(cells, columns["access_level"])

                resource_types = []
                # Continuation rows of a rowspan carry only the per-resource
                # columns, so their offsets start at zero.
                offsets = {
                    key: columns[key]
                    for key in ("resource_type", "condition_keys", "dependent_actions")
                }

                while rowspan > 0:
                    resource_type = cell_text(cells, offsets["resource_type"])
                    condition_keys = cell_paragraphs(cells, offsets["condition_keys"])
                    dependent_actions = cell_paragraphs(
                        cells, offsets["dependent_actions"]
                    )
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
                        row = rows[row_number]
                        cells = row.find_all("td")
                        base = columns["resource_type"]
                        offsets = {
                            key: None if columns[key] is None else columns[key] - base
                            for key in offsets
                        }

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
            if not header_matches("resource types", table) or not header_matches(
                "arn", table
            ):
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

                arn = no_white_space(cells[1].text)
                conditions = []
                for condition in cells[2].find_all("p"):
                    conditions.append(chomp(condition.text))

                service_schema["resources"].append(
                    {"resource": resource, "arn": arn, "condition_keys": conditions}
                )

        # Get condition keys table
        for table in tables:
            if not (
                header_matches("<th> condition keys </th>", table)
                and header_matches("<th> type </th>", table)
            ):
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

                condition = no_white_space(cells[0].text)
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


schema.sort(key=lambda x: x["prefix"])

print(f"--------------------")
# write json to file
iam_definition_file_path = "parliament/iam_definition.json"
with open(
    "parliament/iam_definition.json", "w", encoding="utf-8"
) as iam_definition_file:
    iam_definition_file.write(json.dumps(schema, indent=2, sort_keys=True))
    iam_definition_file.close()

print(f"Updated {iam_definition_file_path}")
