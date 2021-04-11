from setuptools import find_packages
from setuptools import setup

with open("README.md", "r") as readme_file:
    readme = readme_file.read()

requirements = []

setup(
    name="pynipper-ng",
    version="0.1.0",
    author="Syn-4ck",
    author_email="repoJFM@protonmail.com",
    description="",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/syn-4ck/pynipper-ng",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
)