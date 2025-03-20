
from setuptools import setup, find_packages
import os

with open(os.path.join(os.path.dirname(__file__), "requirements.txt"), "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="dearbanana",
    version="0.1.0",
    packages=find_packages(),
    install_requires=requirements
)