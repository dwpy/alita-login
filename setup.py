#!/usr/bin/env python
# -*- coding: utf-8 -*-
import io
import re
from setuptools import setup
from collections import OrderedDict

with io.open('README.md', 'rt', encoding='utf8') as f:
    readme = f.read()

with io.open('alita_login/__init__.py', 'rt', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*?)\'', f.read()).group(1)

setup(
    name='alita-login',
    version=version,
    url='https://github.com/dwpy/alita-login',
    project_urls=OrderedDict((
        ('Documentation', 'https://github.com/dwpy/alita-login'),
        ('Code', 'https://github.com/dwpy/alita-login'),
    )),
    license='BSD',
    author='Dongwei',
    description='alita-login is login extension for Alita。 ',
    long_description=readme,
    long_description_content_type="text/markdown",
    packages=['alita_login'],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    python_requires='>=3.5',
    install_requires=[],
    classifiers=[
        'Development Status :: 1 - Planning',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ]
)
