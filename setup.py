"""Setup script for parliament"""
import os
import re

from setuptools import find_packages, setup


HERE = os.path.dirname(__file__)
VERSION_RE = re.compile(r"""__version__ = ['"]([0-9.]+)['"]""")
TESTS_REQUIRE = ["coverage", "nose"]


def get_version():
    init = open(os.path.join(HERE, "parliament", "__init__.py")).read()
    return VERSION_RE.search(init).group(1)


def get_description():
    return open(
        os.path.join(os.path.abspath(HERE), "README.md"), encoding="utf-8"
    ).read()


setup(
    name="parliament",
    version=get_version(),
    author="Duo Security",
    author_email="scott@summitroute.com",
    description=("parliament audits your AWS IAM policies"),
    long_description=get_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/duo-labs/parliament",
    entry_points={"console_scripts": "parliament=parliament.cli:main"},
    test_suite="tests/unit",
    tests_require=TESTS_REQUIRE,
    extras_require={"dev": TESTS_REQUIRE + ["autoflake", "autopep8", "pylint"]},
    install_requires=["boto3", "jmespath", "pyyaml", "json-cfg"],
    setup_requires=["nose"],
    packages=find_packages(exclude=["tests*"]),
    package_data={
        "parliament": ["iam_definition.json", "config.yaml"],
        "parliament.community_auditors": ["config_override.yaml"],
    },
    zip_safe=True,
    license="BSD 3",
    keywords="aws parliament iam lint audit",
    python_requires=">=3.6",
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3 :: Only",
        "Development Status :: 5 - Production/Stable",
    ],
)
