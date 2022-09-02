from setuptools import setup

setup(
    install_requires=[
        'simplejson',
        'mysqlclient',
        'mysql',
        'MitrettpDB',
        'Flask',
        'Flask-Session'
    ],
    name='MitrettpWEB',
    version='1.0.2',
    packages=[''],
    url='',
    license='',
    author='y.riccardo.gobbo',
    author_email='riccardo.gobbo.2@studenti.unipd.it',
    description='Package to manage data in mitrettp database through a web interface and request data to web API using POST requests'
)
