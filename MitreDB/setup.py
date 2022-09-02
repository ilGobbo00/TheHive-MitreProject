from setuptools import setup

setup(
    install_requires=[
        # 'typing',
        # 'simplejson',
        # 'PyYAML>5',
        # 'mysqlclient',
        # 'treelib',
        # 'urllib3'
        #
        'mysql',
        'mysql-connector-python',
        'PyYAML',
        'typing',
        'treelib',
        'setuptools',
    ],
    name='MitrettpDB',
    version='1.0.2',
    packages=[''],
    url='',
    license='',
    author='y.riccardo.gobbo',
    author_email='riccardo.gobbo.2@studenti.unipd.it',
    description='Package to manage mitrettp database'
)
