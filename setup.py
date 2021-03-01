#!/usr/bin/env python

from setuptools import setup

setup(
    name='target-quickbooks',
    version='1.0.0',
    description='hotglue target for exporting data to Quickbooks API',
    author='hotglue',
    url='https://hotglue.xyz',
    classifiers=['Programming Language :: Python :: 3 :: Only'],
    py_modules=['target_quickbooks'],
    install_requires=[
        'requests==2.20.0',
        'pandas==1.1.3',
        'argparse==1.4.0'
    ],
    entry_points='''
        [console_scripts]
        target-quickbooks=target_quickbooks:main
    ''',
    packages=['target_quickbooks']
)
