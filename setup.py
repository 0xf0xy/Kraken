from setuptools import setup, find_packages

setup(
    name="Kraken",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["scapy"],
    entry_points={
        "console_scripts": [
            "kraken=kraken.cli:main",
        ],
    },
    description="WPA/WPA2 audit toolkit",
    author="0xf0xy",
    license="MIT",
)
