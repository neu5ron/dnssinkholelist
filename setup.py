from distutils.core import setup
import sys
import io

NAME = 'dnssinkholelist'
VERSION = '1.0.2'
AUTHOR = 'neu5ron'
AUTHOR_EMAIL = 'therealneu5ron AT gmail DOT com'
DESCRIPTION = "Combine information about a domain in JSON format"
URL = "https://github.com/neu5ron/dnssinkholelist"
DOWNLOAD_URL = "https://github.com/neu5ron/dnssinkholelist/tarball/master"

LONG_DESCRIPTION = '\n\n'.join([io.open('README.md', 'r',
                                        encoding='utf-8').read(),
                                io.open('CHANGES.md', 'r',
                                        encoding='utf-8').read()])


PACKAGES = ['dnssinkholelist']


INSTALL_REQUIRES = []


if sys.version_info >= (3,):
    print 'Requires python 2.7'
    sys.exit(1)
else:
    INSTALL_REQUIRES.append("requests[security]")
    INSTALL_REQUIRES.append("beautifulsoup")
    INSTALL_REQUIRES.append("pyyaml")

setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    url=URL,
    download_url=DOWNLOAD_URL,
    packages=PACKAGES,
    install_requires=INSTALL_REQUIRES
)