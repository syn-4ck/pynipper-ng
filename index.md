<div style="text-align: center;">
    [![Generic badge](https://img.shields.io/badge/version-0.1.1-white.svg)](https://github.com/syn-4ck/pynipper-ng/releases/tag/v0.1.1-ALPHA)
    [![Generic badge](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/syn-4ck/pynipper-ng/pulls)
    [![Generic badge](https://img.shields.io/badge/production-no-red.svg)](https://github.com/syn-4ck/pynipper-ng/releases/tag/v0.1.1-ALPHA)
    [![Generic badge](https://img.shields.io/badge/CI/CD-passed-green.svg)](#contributing)
</div>

## Table of contents
1. [What is pynipper-ng](#what-is-pynipper-ng)
2. [Install](#install)
3. [Quickstart](#quickstart)
4. [More information](#more-information)
5. [References](#references)

## What is pynipper-ng?
pynipper-ng is a configuration security analyzer for network devices. The goal of this tool is check the vulnerabilities and misconfigurations of routers, firewalls and switches reporting the issues in a simple way.

This tool is based on [nipper-ng](https://github.com/arpitn30/nipper-ng), updated and translated to Python. The project wants to improve the set of rules that detect security misconfigurations of the network devices due to the new architecture (using Python pynipper modules). 

## Install

The requirements are:

* Python 3.7.x or latest
* PIP

### PIP install

You can install pynipper-ng with PIP using the wheel package linked in each version of the tool.

```BASH
pip install pynipper_ng-<VERSION>-py3-none-any.whl
```

It will be in `pypi` registry soon.

### Source code install

```BASH
python setup.py build install
```

## Quickstart

```BASH
pynipper-ng -d IOS_ROUTER -i tests\test_data\cisco_ios_example.conf -o HTML -f ./report.html -x
```

## More information

### Contributing

Contribution are welcome! Please follow the steps defined in CONTRIBUTING file and share your improvements with the community.

[![CodeQL](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml)
[![SonarCloud Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=pynipper-ng&metric=alert_status)](https://sonarcloud.io/dashboard?id=pynipper-ng)
[![Flake8 CI](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml)
[![Detect-secrets](https://github.com/syn-4ck/pynipper-ng/actions/workflows/detect-secrets.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/detect-secrets.yml)
[![Snyk SCA Analysis](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml)

### CISCO IOS API integration

Get your credentials and put into the configuration file.

### Pynipper modules

Pynipper-ng detects device configuration weaknesses based on modules. Pynipper modules checks into the network device configuration with regex if a property is set or not, and report it when this is not secure.

#### Pynipper modules summary

For Cisco IOS:

| MISCONFIGURATION | CHECKS                                      | MODULE NAME  | LABEL  | NOTE  |
|------------------|---------------------------------------------|--------------|--------|-------|
| HTTP MISCONFIG   | Use HTTP admin, ACL and AUTH                | http_module  | http   |       |
| SSH MISCONFIG    | Use SSH admin, use v2, retries and timeout  | ssh_module   | ssh    |       |

#### Implements your modules

You can also implements your modules. Pynipper-ng has not a option to incorporate it by CLI or similar, but contributions are welcome! With a contribution, you can help a lot of users with the same problem and you can improve the community :).

## References
[nipper-ng](https://github.com/arpitn30/nipper-ng)