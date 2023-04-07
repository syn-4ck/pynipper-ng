# Install pynipper-ng

**pynipper-ng** is created in `Python 3`, so it is available in Linux, Windows and MacOS systems.

## Prerequisites

- Python >= 3.6
- pip3

OR

- docker

## Download and install with Python 3

To install pynipper-ng in your device you only should follow this steps:

1. Go to the [latest release](https://github.com/syn-4ck/pynipper-ng/releases/latest).
2. Download the attached wheel: `pynipper_ng-<version>-py3-none-any.whl`
3. Run `pip install pynipper_ng-<version>-py3-none-any.whl`

#### pynipper-ng will be in [pypi](https://pypi.org/) soon!

## Run it with Docker

To run a Linux Docker container from the official image, you should follow this steps:

1. Go to the [image version](https://hub.docker.com/repository/docker/ghsyn4ck/pynipper-ng/tags?page=1&ordering=last_updated) in Docker Hub.
2. Pull the image using: `docker pull ghsyn4ck/pynipper-ng:<tag>`, where "tag" is the tag needed.
3. Run the container using: `docker run -it --mount source=<dir>,destination=/usr/share/files ghsyn4ck/pynipper-ng:<tag>`, where "dir" is your directory with the files (like the device configuration file or your pynipper-ng configuration file).
4. Enjoy!

