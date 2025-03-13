from setuptools import setup, find_packages

setup(
    name="docker-vulnerability-scanner",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'docker>=6.1.3',
        'click>=8.1.7',
        'rich>=13.7.0',
        'trivy-sdk>=0.5.5',
        'PyYAML>=6.0.1',
        'requests>=2.31.0',
        'python-debian>=0.1.49',
        'Flask>=3.0.2',
        'Flask-WTF>=1.2.1',
        'Bootstrap-Flask>=2.3.3',
    ],
    entry_points={
        'console_scripts': [
            'docker-vuln-scan=scanner:cli',
        ],
    },
    data_files=[
        ('lib/docker-vulnerability-scanner/templates', [
            'templates/base.html',
            'templates/index.html',
            'templates/containers.html',
            'templates/scan_results.html',
        ]),
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="Docker Container Vulnerability Scanner for Astra Linux",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    keywords="docker security vulnerability scanner astra-linux",
    url="https://github.com/yourusername/docker-vulnerability-scanner",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
    ],
) 