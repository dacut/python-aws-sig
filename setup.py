#!/usr/bin/env python3
from __future__ import absolute_import, division, print_function
from os.path import dirname
from sys import version_info
from setuptools import setup, Command

import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("nose").setLevel(logging.DEBUG)

setup_requires=[]
if version_info[0] > 3 or (version_info[0] == 3 and version_info[1] >= 5):
    setup_requires.append("Sphinx>=1.3")

with open(dirname(__file__) + "/README.rst", "r") as fd:
    readme = fd.read()

setup(
    name="awssig",
    version="0.3.2",
    packages=['awssig'],
    install_requires=["six>=1.0"],
    setup_requires=setup_requires,

    # PyPI information
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    description="AWS signature verification routines",
    long_description=readme,
    long_description_content_type="text/x-rst",
    license="Apache 2.0",
    url="https://github.com/dacut/python-aws-sig",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords = ['aws', 'signature', 'aws-sigv4'],
    zip_safe=False,
)
