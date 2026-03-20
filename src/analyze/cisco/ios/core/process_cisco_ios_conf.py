import array
import importlib
import pkgutil

from .. import plugins as plugs


def _import_modules() -> array:
    pkg = plugs.__package__
    modules = []
    module_names = []

    for _, modname, _ in pkgutil.iter_modules(plugs.__path__):
        if modname != "generic_plugin" and modname.endswith("_plugin"):
            module_name = f"{pkg}.{modname}"

            importlib.import_module(module_name)
            spec = importlib.util.find_spec(module_name)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            module_names.append(module.__name__)
            modules.append(module)

    return modules


def _classesinmodule(module):
    md = module.__dict__
    return [
        md[c] for c in md if (
            isinstance(md[c], type) and md[c].__module__ == module.__name__
        )
    ]


def process_cisco_ios_conf(filename: str) -> dict:
    reported_issues = {}
    i = []
    idx = 2

    for module in _import_modules():
        issues = {}
        for module_class in _classesinmodule(module):
            m = module_class()
            m.analyze(filename)
            i = m.get_issues()
            issues = _generate_section(i, issues, idx)
            reported_issues[f"2.{idx} {m.name()}"] = issues
            idx += 1

    return reported_issues


def _generate_section(issues: array, issue_dict: dict, index: int) -> dict:
    subindex = 0
    for issue in issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issue_dict[title] = issue
        subindex += 1
    return issue_dict
