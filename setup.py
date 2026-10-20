from setuptools import setup, find_packages

setup(
    name="secguard",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "secguard=secguard.cli:main",
        ],
    },
    python_requires=">=3.8",
    author="Alex",
    description="DevSecOps SAST & Secret Scanner with Shannon Entropy",
)
