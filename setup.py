import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.txt')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = [
    'automatron',
    'pyOpenSSL',
]

setup(
    name='automatron-youtube-playlist',
    version='1.0.0',
    description='Automatron IRC bot - YouTube playlist plugin',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Twisted",
        "Topic :: Internet :: IRC",
    ],
    author='Ingmar Steen',
    author_email='iksteen@gmail.com',
    url='',
    keywords='',
    packages=find_packages() + ['twisted.plugins'],
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    scripts=[
        'scripts/automatron-youtube-setup',
    ]
)
