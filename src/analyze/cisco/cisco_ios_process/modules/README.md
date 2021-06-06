# Cisco Modules

## CIS Benchmarks used

- **CIS Benchmark for Cisco IOS 12 v4.0.0**
- **CIS Benchmarks for Cisco IOS 15 v4.1.0**
- **CIS Benchmarks for Cisco IOS 16 v1.1.1**

## How to create a module

To create a new module, you should create 1 to N checks. Each check needs a `Detector` and a `Vuln creator`. Finally, the module needs a `main function` that calls all `Vuln creator` methods.

### Detector

A function that detects with regex some configuration patterns to get misconfigurations. You have the `parse_cisco_ios_config_file` method available to parse the file.

Example: 

```python
def _name_detector(filename: str) -> [output_type]:
    parser = parse_cisco_ios_config_file(filename)
    object_parsed = parser.find_objects("get some object")
    if (len(object_parsed) > 0):
        prop = object_parsed[0].re_match_typed(
            r'^regex', default='')
        return prop
    else:
        return None
```

### Vuln creator

This function use `Detector` methods to check if a issue exists. If a condition is true, the `Vuln creator` function must append a new issue with some information.

Example:

```python
def vuln_creator(issues: list, filename: str):
    if (_name_detector(filename)==some_value):
        issue = CiscoIOSIssue(
            "Title",
            "Description",
            "Impact",
            "Exploit ease",
            "Recommendation"
        )
        issues.append(issue)
```

### Main function

The module has a main function to be called in the parent function and get all module issues.

Example: 

```python
def module_name(filename: str) -> list:
    issues = []
    vuln_creator1(issues, filename)
    vuln_creator2(issues, filename)
    ...
    return issues
```

## Available Cisco Modules

| MISCONFIGURATION | CHECKS                                      | MODULE NAME  | LABEL  | NOTE  |
|------------------|---------------------------------------------|--------------|--------|-------|
| HTTP MISCONFIG   | Use HTTP admin, ACL and AUTH                | http_module  | http   |       |
| SSH MISCONFIG    | Use SSH admin, use v2, retries and timeout  | ssh_module   | ssh    |       |
|                  |                                             |              |        |       |
