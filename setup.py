try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'name': 'bootstrapper',
    'description': 'Bootstrap new machines.',
    'author': 'Hannes Koerber',
    'url': 'https://github.com/whatevsz/virt-bootstrap',
    'download_url': 'https://github.com/whatevsz/virt-bootstrap',
    'author_email': 'hannes.koerber+bootstrapper@gmail.com',
    'version': '0.1',
    'install_requires': [],
    'packages': [
        'bootstrapper',
        'bootstrapper.creators',
    ],
    'scripts': ['bin/bootstrap']
}

setup(**config)
