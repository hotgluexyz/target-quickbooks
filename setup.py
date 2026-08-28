#!/usr/bin/env python

from setuptools import setup

setup(
    name='target-quickbooks',
    version='1.0.22',
    description='hotglue target for exporting data to Quickbooks API',
    author='hotglue',
    url='https://hotglue.xyz',
    classifiers=['Programming Language :: Python :: 3 :: Only'],
    python_requires='>=3.7.1',
    py_modules=['target_quickbooks'],
    install_requires=[
        'requests>=2.20.0',
        'backoff>=1.8.0',
        'numpy>=1.17.3,<2; python_version < "3.9"',   # pandas 1.3.5 binary built for numpy 1.x; numpy 2.x causes ABI error
        'pandas==1.3.5; python_version < "3.9"',
        'numpy>=1.26.0; python_version >= "3.9"',
        'pandas>=2.3.3; python_version >= "3.9"',
        'argparse==1.4.0'
    ],
    entry_points='''
        [console_scripts]
        target-quickbooks=target_quickbooks:main
    ''',
    packages=['target_quickbooks']
)
