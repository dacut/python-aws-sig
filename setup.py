#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from setuptools import setup, Command

import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("nose").setLevel(logging.DEBUG)

setup(
    name="awssig",
    version="1.0",
    packages=['awssig'],
    install_requires=["boto>=2.0", "pycrypto>=2.6", "six>=1.0"],
    setup_requires=["nose>=1.0", "coverage>=4.0"],

    # PyPI information
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    description="AWS signature verification routines",
    license="BSD",
    url="https://github.com/dacut/python-aws-sig",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords = ['aws', 'signature'],
    zip_safe=False,
)
