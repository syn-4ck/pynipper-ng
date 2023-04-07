FROM python:3.9-slim

COPY . /app/

WORKDIR /app

RUN python setup.py build install
