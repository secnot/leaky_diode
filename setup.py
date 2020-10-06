from setuptools import setup
import pathlib


# Extract README as the long description
HOME_PATH = pathlib.Path(__file__).parent
README = (HOME_PATH/"README.md").read_text()

short_description = """Leaky Diode is a data exfiltration test tool for data diodes,
    using flow modulation and close delay attacks"""


setup(
    name="leaky_diode",
    version="0.1",
    description=short_description,
    long_description=README,
    long_description_content_type="text/markdown",

    # Homepage
    url='https://github.com/secnot/leaky_diode',

    # Author details
    author='SecNot',
    author_email='secnot@secnot.com',

    # License
    license = 'AGPLv3',

    # App information
    keywords = ['data diode', 'diode', 'cybersecurity', 'security', 'hack', 'hacking',
        'data', 'leak', 'exfiltration', 'data exfiltration', 'flow modulation', 
        'close delay', 'attack', 'pentesting', 'penetration testing'],

    Classifiers = [
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Development Status :: 3 - Alpha',
        'Operating System :: POSIX :: Linux',
        'Topic :: Security',
        'Topic :: Terminals',
    ],

    # Package
    packages=["leaky_diode"],
    scripts=[
        "bin/leaky_server",
        "bin/leaky_client"
    ],

    zip_safe = True,
)



