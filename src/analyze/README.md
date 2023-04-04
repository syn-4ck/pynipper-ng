# Device analysis

## Plugins

To detect misconfigurations in network devices, pynipper-ng uses a regex engine based on plugins.

Plugins are python classes with a `analyze` method that searches in the configuration file and reports vulnerable patterns. This plugins are splitted by protocols, goals or tecnologies.

### Available plugins

**Cisco IOS devices**

| Plugin name          | Scan goal                                        |
|----------------------|--------------------------------------------------|
| http_plugin          | Detect HTTP misconfigurations                    |
| ssh_plugin           | Detect SSH misconfigurations                     |
| dns_plugin           | Detect DNS misconfigurations                     |
| username_plugin      | Detect misconfigurated passwords in OS           |

### Create new plugins

To create your own plugins you need to create a new file in `./<device_type>/plugins` named `<something>_plugin.py` and develop a new class. The class must:

* Extend `./<device_type>/core/base_plugin.py`
* Override the `def analyze(self, config_file):` function

You can see the other plugins to verify your implementation.
