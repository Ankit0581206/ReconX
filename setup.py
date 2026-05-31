from setuptools import setup, find_packages

setup(
    name="reconx",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
        "dnspython>=2.6.1",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "reconx=reconx.cli:cli",
        ],
    },
    author="Ankit",
    description="Automated Reconnaissance Framework for Bug Bounty Hunting",
    python_requires=">=3.9",
)
