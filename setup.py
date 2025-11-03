"""
Setup script for PangCrypter.
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="pangcrypter",
    version="1.0.0",
    author="Pang HQ",
    author_email="",
    description="A secure text editor with encryption capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Pang-Dev/PangCrypter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Text Editors",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-qt>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pangcrypter=pangcrypter.main:main",
        ],
    },
    scripts=["run.py"],
    include_package_data=True,
    package_data={
        "pangcrypter": [
            "*.ico",
            "*.svg",
            "*.json",
        ],
    },
    keywords="encryption security text-editor cryptography",
    project_urls={
        "Bug Reports": "https://github.com/Pang-Dev/PangCrypter/issues",
        "Source": "https://github.com/Pang-Dev/PangCrypter",
    },
)
