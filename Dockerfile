# Pynipper-ng Docker construction
FROM python:3.9-slim

RUN pip install pip --upgrade
RUN pip install setuptools --upgrade

COPY . /app/

WORKDIR /app

RUN python setup.py build install

RUN useradd -u 8877 pynipper-ng
USER pynipper-ng
