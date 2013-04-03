from distutils.core import setup

setup(name="simpleRPL",
     version="0.1",
     description="a simple RPL implementation",
     author="Tony Cheneau",
     author_email="tony.cheneau@nist.gov",
     packages=["RPL"],
     scripts=["simpleRPL.py", "cliRPL.py"],
     )
