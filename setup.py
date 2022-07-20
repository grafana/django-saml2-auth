"""The setup module for django_saml2_auth.
See:
https://github.com/grafana/django_saml2_auth
"""

from codecs import open
from setuptools import (setup, find_packages)
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

# Extract requirements from requirements.txt
requirements = [r.rstrip() for r in open("requirements.txt").readlines()]

setup(
    name="grafana_django_saml2_auth",

    version="3.8.0",

    description="Django SAML2 Authentication Made Easy.",
    long_description=long_description,
    long_description_content_type="text/markdown",

    url="https://github.com/grafana/django-saml2-auth",

    author="Fang Li",
    author_email="surivlee+djsaml2auth@gmail.com",

    maintainer="Mostafa Moradian",
    maintainer_email="mostafa@grafana.com",

    license="Apache 2.0",

    classifiers=[
        "Development Status :: 5 - Production/Stable",

        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",

        "License :: OSI Approved :: Apache Software License",

        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],

    keywords=[
        "django",
        "saml",
        "saml2"
        "sso",
        "authentication",
        "okta",
        "standard"
    ],

    packages=find_packages(),

    install_requires=requirements,
    include_package_data=True,
)
