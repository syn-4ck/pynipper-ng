class DeviceConfigurationFileNotFound(Exception):
    def __init__(self, m):
        self.message = m
    def __str__(self):
        return self.message

class PynipperConfigurationFileNotFound(Exception):
    def __init__(self, m):
        self.message = m
    def __str__(self):
        return self.message