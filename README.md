# pynipper-ng

[![CodeQL](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/codeql-analysis.yml)
[![GitGuardian scan](https://github.com/syn-4ck/pynipper-ng/actions/workflows/gitguardian-scan.yml/badge.svg)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/gitguardian-scan.yml)
[![Snyk SCA Analysis](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/snyk.yml)
[![SonarCloud Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=syn-4ck_pynipper-ng&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=syn-4ck_pynipper-ng)
[![Flake8 CI](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml/badge.svg?branch=main)](https://github.com/syn-4ck/pynipper-ng/actions/workflows/flake8.yml)


## Table of contents
1. [What is pynipper-ng](#what-is-pynipper-ng)
2. [Install](#install)
3. [Quickstart](#quickstart)
4. [More information](#more-information)
5. [References](#references)

## What is pynipper-ng?
pynipper-ng is a **configuration security analyzer for network devices**. The goal of this tool is check the vulnerabilities and misconfigurations of routers, firewalls and switches reporting the issues in a simple way.

This tool is based on [nipper-ng](https://github.com/arpitn30/nipper-ng), updated and translated to Python. The project wants to improve the set of rules that detect security misconfigurations of the network devices using multiple standard benchmarks (like [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)) and integrate the tool with APIs (like [PSIRT Cisco API](https://developer.cisco.com/docs/psirt/#!overview/overview)) to scan known vulnerabilities. 

## Install

The requirements are:

* Python 3
* Pip to Python 3

### Python install

You can install pynipper-ng with pip using the wheel package linked in each version of the tool.

```BASH
pip install pynipper_ng-<VERSION>-py3-none-any.whl
```

_It will be in `pypi` registry soon._

### Source code install

Clone this repository and run:

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
| -x   | --offline         | Disable APIs integration                                                                                     | NO         | True             |
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

Available plugins: [check here](src/analyze/README.md)

#### Implements your modules

You can implements your own modules. You should clone the repository and create the plugins in `src/analyze/cisco/<device_type>/plugins`. To improve the pynipper-ng tool you can contribute adding your work :).

To create your own plugins, follow [this guidelines](src/analyze/README.md)

## References
[nipper-ng](https://github.com/arpitn30/nipper-ng)
