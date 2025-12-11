"""
Setup script for IPTables Agent
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="iptables-agent",
    version="0.1.0",
    author="IPTables Agent Contributors",
    description="Automatic agent to explain iptables rules in human-readable format",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vinupalackal/iptables_agent",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "iptables-agent=iptables_agent.cli:main",
        ],
    },
)
