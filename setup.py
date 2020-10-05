from setuptools import setup

long_description = """Leaky Diode is a data exfiltration test tool for data diodes,
    it uses flow modulation and close delay attacks"""


setup(
    name="leaky_diode",
    version="0.1",
    description=long_description,

    # Homepage
    url='https://github.com/secnot/leaky_diode',

    # Author details
    author='SecNot',

    # License
    license = 'AGPLv3',

    # App information
    keywords = ['data diode', 'diode', 'cybersecurity', 'security', 'hack', 'hacking',
        'data', 'leak', 'exfiltration', 'data exfiltration', 'flow modulation', 
        'close delay', 'attack'],

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



