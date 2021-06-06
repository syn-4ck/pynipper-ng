# pynipper-ng

[![CodeQL](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml)
[![SonarCloud Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=pynipper-ng&metric=alert_status)](https://sonarcloud.io/dashboard?id=pynipper-ng)
[![Flake8 CI](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml)
[![Detect-secrets](https://github.com/syn-4ck/pynipper-ng/actions/workflows/detect-secrets.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/detect-secrets.yml)
[![Snyk SCA Analysis](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml)


## Table of contents
1. [What is pynipper-ng](#what-is-pynipper-ng)
2. [Install](#install)
3. [Quickstart](#quickstart)
4. [More information](#more-information)
5. [References](#references)

## What is pynipper-ng?
pynipper-ng is a **configuration security analyzer for network devices**. The goal of this tool is check the vulnerabilities and misconfigurations of routers, firewalls and switches reporting the issues in a simple way.

This tool is based on [nipper-ng](https://github.com/arpitn30/nipper-ng), updated and translated to Python. The project wants to improve the set of rules that detect security misconfigurations of the network devices using multiple standard benchmarks ([CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)) and integrate with APIs (like [PSIRT Cisco API](https://developer.cisco.com/docs/psirt/#!overview/overview)) to scan known vulnerabilities. 

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

## Quickstart and options

### Quickly demo

```BASH
pynipper-ng -d IOS_ROUTER -i tests\test_data\cisco_ios_example.conf -o HTML -f ./report.html -x
```

### Options

| Flag | OPTION        | DESCRIPTION                                                                                                      | MANDATORY? | DEFAULT VALUE |
|------|---------------|------------------------------------------------------------------------------------------------------------------|------------|--------------|
| -h   | --help        | Display a help message                                                                                           | NO         | N/A             |
| -d   | --device      | Device type to analyze (1)                                                                                       | YES        |             |
| -i   | --input       | Configuration device file to analyze (file contains standard output redirection of `show configuration` command) | YES        |             |
| -o   | --output-type | Report type (HTML or JSON)                                                                                       | NO         | HTML          |
| -f   | --output-filename | Report filename                                                                                              | NO         | report.html
| -x   | --offline         | Disable APIs integration                                                                                     | NO         | N/A             |
| -c   | --configuration   | Configuration file to pynipper-ng (2)                                                                        | NO         | default.conf    |


(1) Check [here](src/devices/README.md) the devices supported

(2) Check [Pynipper-ng configuration file](#config-file) to know more about it.

## More information

### Pynipper-ng Configuration File

The configuration file is used to define some properties and customize the scans.

#### Pynipper-ng Configuration File: PSIRT Cisco API

To use the PSIRT Cisco API you must provide the API keys. To get it: [https://apiconsole.cisco.com/](https://apiconsole.cisco.com/)

```conf
[Cisco]
CLIENT_ID = <your-client-id>
CLIENT_SECRET = <your-client-secret-token>
```

### Contributing

Contribution are welcome! Please follow the steps defined in CONTRIBUTING file and share your improvements with the community.

### CISCO IOS API integration

Get your credentials and put into the configuration file.

### Pynipper modules

Pynipper-ng detects device configuration weaknesses based on modules. Pynipper modules checks into the network device configuration with regex if a property is set or not, and report it when this is not secure.

#### Pynipper modules summary

Cisco IOS Modules: [check here](src/analyze/cisco/cisco_ios_process/modules/README.md)

#### Implements your modules

You can also implements your modules. Pynipper-ng has not a option to incorporate it by CLI or similar, but contributions are welcome! With a contribution, you can help a lot of users with the same problem and you can improve the community :).

To create your own modules, follow [this guidelines](src/analyze/README.md)

## References
[nipper-ng](https://github.com/arpitn30/nipper-ng)
