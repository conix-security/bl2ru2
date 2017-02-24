#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup
import bl2ru2


setup(
    name = 'bl2ru2',
    packages = ['bl2ru2'],
    version = bl2ru2.__version__,
    description = 'A suricata rule generator',
    author = 'Robin Marsollier',
    author_email = 'robin.marsollier@conix.fr',
    maintainer='Robin Marsollier',
    url = 'https://github.com/conix-security/bl2ru2',
    keywords = ['suricata', 'ioc', 'ids'],
    classifiers = [
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ],
)
