# Contributing guide

Thank you for investing your time in contributing to our project! Any contribution you make will be reflected on [authors](AUTHORS.md) ✨.

<!-- Add code of conduct here -->

## New Contributor Guide

To get an overview of the project, read the [README](README.md). Here are some resources to help you get started with open source contributions:

- [Security Assertion Markup Language](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)
- [SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0)
- [SAML metadata](https://en.wikipedia.org/wiki/SAML_metadata)

This library is tested against these SAML SSO identity providers. You can probably open development accounts on these platforms to test your Django with SAML SSO.

- Okta
- Azure Active Directory
- PingOne
- Auth0 (doesn't support custom attributes)

For debugging your setup, you can use SAML-tracer add-on on [Firefox](https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/) or extension on [Chrome](https://chrome.google.com/webstore/detail/saml-tracer/mpdajninpobndbfcldcmbpnnbhibjmch?hl=en), which will help you capture SAML SSO traffic and shows you what is passed around in the HTTP messages.

Read the [tests](django_saml2_auth/tests) to learn more about settings and how each function or endpoint works. And when you open a PR, please add tests and documentation. You can also add your name to the list of [authors](AUTHORS.md). When the PR is ready, mention  for the review.

## How to Contribute

1. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
2. Fork [the repository](http://github.com/loadimpact/django-saml2-auth) on GitHub to start making your changes to the **master** branch (or branch off of it).
3. Write a test which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug the maintainer ([@mostafa](https://github.com/mostafa)) until it gets merged and published. :) Make sure to add yourself to [authors](AUTHORS.md).

## When you raise an issue or open a PR

Please note this library is mission-critical and supports almost all django versions since 2.2.x. We need to be extremely careful when merging any changes.

The support for new versions of django are welcome and I'll make best effort to make it latest django compatible.
