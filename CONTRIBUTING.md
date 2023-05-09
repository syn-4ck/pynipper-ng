# Contributing to pynipper-ng

Welcome developer, thanks for contributing!

Reading and following these guidelines will help me make the contribution process easy and effective for everyone involved. It also communicates that you agree to respect the time of the developers managing and developing these open source projects. In return, we will reciprocate that respect by addressing your issue, assessing changes, and helping you finalize your pull requests.

## Quicklinks

- [Contributing to pynipper-ng](#contributing-to-pynipper-ng)
  - [Code of Conduct](#code-of-conduct)
  - [Getting Started](#getting-started)
    - [Issues](#issues)
    - [Pull Requests](#pull-requests)
  - [Core changes](#core-changes)
    - [Implement a new device](#new-device)
    - [Implement a new plugin](#new-plugin)

## Code of Conduct

We take our open source community seriously and hold ourselves and other contributors to high standards of communication. By participating and contributing to this project, you agree to uphold our [Code of Conduct](https://github.com/syn-4ck/pynipper-ng/blob/master/CODE_OF_CONDUCT.md).

## Getting Started

Contributions are made to this repo via Issues and Pull Requests (PRs). A few general guidelines that cover both:

- To report security vulnerabilities, please check our [Security guide](https://github.com/syn-4ck/pynipper-ng/blob/master/SECURITY.md).
- Search for existing Issues and PRs before creating your own.
- We work hard to makes sure issues are handled in a timely manner but, depending on the impact, it could take a while to investigate the root cause. A friendly ping in the comment thread to the submitter or a contributor can help draw attention if your issue is blocking.

### Issues

Issues should be used to report bugs, request a new feature, or to discuss potential changes before a PR is created. When you create a new Issue, a template will be loaded that will guide you through collecting and providing the information we need to investigate. You should use the appropiate template, based on this criteria:

- **Bug report**: Any thing is not working properly.
- **Feature request**: Any thing that improves the tool's behaviour.
- **Report a security vulnerability**: Any security issue.
- **New version**: A new planned version release.
- **Another issue**: Any question/improvement about the tool.

Please, fill the template issues with all possible data, attaching screenshots and detailed information. We will review, tag and assign this issues soon.

**Any change made** to the repository **must be followed by an issue**, approved and reviewed by the tool's owner.

### Pull Requests

PRs are always welcome and can be a quick way to get your fix or improvement. In general, PRs should:

- Only fix/add the functionality in question.
- Include documentation and a properly description in the repository.
- Must be correctly tested.
- All actions must be passed.

In general, we follow a fork model:

1. Fork the repository to your own Github account.
2. Clone the project to your machine.
3. Create a branch locally with a succinct but descriptive name.
4. Install pre-commit with `pip install pre-commit` and configure it with `pre-commit install`.
5. Commit changes to the branch.
6. Following any formatting and testing guidelines specific to this repo.
7. Push changes to your fork.
8. Open a PR in our repository. The PR must be merged into the pynipper-ng **develop** branch.

The **Pull Request may reference the Issue** with the detailed description, adding a `Context` and the `Acceptance criteria`.

## Core changes

To implement new functionalities (new `plugins` and `devices`) you should read the following guidelines.

### New device

To create a new supported device:

1. Generate a new directory tree:

```
pynipper-ng/src/analyze/<device-type>/<device-subtype>
 |
 |-- /api (optional)
 |   |
 |   |-- <device-type>_vulns_service.py
 |   |
 |   |-- <device-type>_vuln.py
 |
 |-- /core
 |   |
 |   |-- base_plugin.py
 |   |
 |   |-- process_<device-type>_conf_.py
 |
 |-- /plugins
 |
 |-- analyze_<device-type>_device.py
```

Use the `core` directory to store the base plugin (child of `src/analyze/common/base_plugin/base_plugin.py`) and the process configuration file class to detect the issues.

Use the `plugins` directory to store all plugins.

Use `api` directory if you have some API REST integration to get known vulnerabilities.

Finally, use the `analyze_<device-type>_device.py` main file to process the analysis.

2. Use the `src/analyze/common` classes to standarize the use between devices:

- `base_plugin/base_plugin.py`: A father plugin, the base of all plugins of all devices.
- `issue/issue.py`: The issue architecture. All misconfiguration issues must have the same fields and methods.
- `passwords/password_utils.py`: A util's methods to check password strength.

3. Implement the code based on another device example, like Cisco.

4. Add the new device type in `src/devices/common/types.py` and in `src/devices/README.md`.

5. Add the new device in `analyze_device` method into `src/analyze/analyze_device.py`.

6. Document the information in the `SUPPORTED_DEVICES.md`.

__This guideline is under construction and continuos improvement. Any change in this procedure is welcome!__ 

### New plugin

To detect misconfigurations in network devices, pynipper-ng uses a regex engine based on plugins.

Plugins are python classes with an `analyze` method that searches in the configuration file and reports vulnerable patterns. This plugins are splitted by protocols, goals or tecnologies.

To create your own plugins you need to create a new file in `./<device_type>/plugins` named `<something>_plugin.py` and develop a new class. The class must:

* Extend from `./<device_type>/core/base_plugin.py`.
* Override the `def analyze(self, config_file)` function.

Example of plugin

```python
class MyNewPlugin(GenericPlugin):
  def _get_cisco_ios_ssh_interface(self, filename: str) -> str:
    parser = self.parse_configuration(filename)
    vulnerability_regex = parser.find("non-compliant conf")
    return vulnerability_regex

  def get_prop(self, filename: str):
    if (self._is_vulnerable(filename)):
      return Issue(
        "Title",
        "Observation",
        "Impact",
        "Ease",
        "Recommendation"
      )
    return None

  def analyze(self, config_file) -> None:
    issues = []

    issues.append(self.get_prop(config_file))

    for issue in issues:
      if issue is not None:
        self.add_issue(issue)
```

__This guideline is under construction and continuos improvement. Any change in this procedure is welcome!__ 

## Doubts or issues contributing

If you need help contributing to this repository, contact with the owner by email: repoJFM@protonmail.com. 🇬🇧/🇺🇸 or 🇪🇸 
