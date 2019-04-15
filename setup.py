#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name="tuf_vectors",
    version="0.0.0",
    author="heartsucker",
    author_email="heartsucker@autistici.org",
    description="Generates TUF/Uptane test vectors",
    install_requires=[
        'Jinja2>=2.10.1',
    ],
)
