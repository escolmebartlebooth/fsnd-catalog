# Udacity Full Stack Nano-Degree: Item Catalog

## Author etc

created by David Escolme
last updated on 07 May 17
last update on 18 Sep 17 - added POSTGRES support

## Installation

### Pre-Requisites

+ Virtual Environment: virtual box and vagrant
    + download and install virtual box for your environment: https://www.virtualbox.org/wiki/Downloads
    + note that for windows 10 users, my experience is that version 4.3 works and version 5 does not work
    + you will have to work out which one does / does not work for you - the problem relates to starting vagrant
    + you do not need to test the install as the next part does this
    + download and install vagrant: https://www.vagrantup.com/downloads.html
    + test by opening a command line and: vagrant --version
    + create and configure a virtual environment using the FSND-Virtual-Machine.zip: https://d17h27t6h515a5.cloudfront.net/topher/2016/December/58488015_fsnd-virtual-machine/fsnd-virtual-machine.zip
    + download the zip and extract to an appropriate folder
    + once downloaded, issue vagrant up from the /vagrant folder created, this will download and configure the environment as it will be the first time is has run
    + once configured...issue vagrant ssh to login to the virtual environment
+ Python - version 2.7.6
    + the python environment should also come with the configuration of the virtual environment
+ Python Libraries
    + the principle library used is Flask, which again should be part of the virtual environment
    + other libraries used are SQLAlchemy, Jinja2
+ Database
    + this app uses sqllite as the database engine: http://www.tutorialspoint.com/sqlite/sqlite_installation.htm

### Files

+ /
    /test-data
        files that create and then can query test data: do not use without reviewing their contents
    /static
        styles.css: home for css
    /templates
        *.html: files used to render pages, base.html and navigation.html are used across the site
    catalog_database_setup.py: creates the models using sqlalchemy
    *.json: secrets files for amazon and google login
    itemcatalog.db: the database
    itemcatalog.py: the main application

## Usage

+ After completing the installation steps
    + start the virtual environment: command: vagrant up from: Home directory of virtual environment
    + connect to the virtual environment: command: vagrant ssh
    + check python is operational
    + navigate to the directory where itemcatalog.py resides
    + create the database: command: python <file> where <file> is the <directory>/catalog_database_setup.py file
    + run the application using: python itemcatalog.py

+ User Instructions / Capabilities
    + pre-login: View Items (/ or /categories); View Item, View Category
    + login (amazon or google)
    + logout
    + post login: New, Edit, Delete Category, New, Edit, Delete Item
