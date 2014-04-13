from setuptools import setup

setup(
    name='python-whois',
    description='unix-like whois utility in pure python',
    version='1.0.0',
    author='Sergei Khoroshilov',
    author_email='kh.sergei@gmail.com',
    license='The MIT License',
    py_modules=['whois'],
    install_requires=['six'],
    tests_require=['six', 'mock'],
    include_package_data=True,
)