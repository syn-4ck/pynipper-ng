FROM python:3.9-slim

RUN pip install pip --upgrade
RUN pip install setuptools --upgrade

RUN useradd -u 8877 pynipper-ng
USER pynipper-ng

COPY . /app/

WORKDIR /app

RUN python setup.py build install
