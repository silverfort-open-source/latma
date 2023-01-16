from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="latma",
    version="1.0.0",
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'eventlogcollector=latma.eventlogcollector:main',
        ]
    }
)
