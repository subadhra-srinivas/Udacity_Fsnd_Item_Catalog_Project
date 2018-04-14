# Udacity_Fsnd_Item_Catalog_Project

## Introduction:

Modern web applications perform a variety of functions and provide amazing features and utilities to their users; but deep down, it’s really all just creating, reading, updating and deleting data. We developed an application that provides  list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.


## Important Files:

item_catalog_project.py: This file contains the server side program</br>

categoriesitem.db: Database file which contains some sports related items. In order to create the database you have to run the database_setup.py. In order to populate the database run lotsofitem.py</br>

client_secrets.json and fb_client_secrets.json: This file contains authorization information for Google+ and Facebook</br>

## Requirements:

This project has been run from vagrant virtual machine</br>

Python 2.7</br>
SQLite</br>
SQLAlchemy</br>
Flask</br>
httplib2, oauth2client and Requests(Python libraries)</br>

## How to run the project:

Install Vagrant and VirtualBox</br>
Clone the fullstack-nanodegree-vm</br>
Launch the Vagrant VM (vagrant up)</br>
Write your Flask application locally in the vagrant/catalog directory (which will automatically be synced to /vagrant/catalog within the VM).</br>
Run your application within the VM (python /vagrant/catalog/item_catalog_project.py)</br>
Access and test your application by visiting http://localhost:5000 locally</br>

## Screenshots:

![ScreenShot](https://github.com/subadhra-srinivas/Udacity_Fsnd_Item_Catalog_Project/blob/master/vagrant/catalog/item_catalog-600_medium.png)

## Description of obstacles and solution:

I had problems implementing OAuth for login. Read the OAuth documentation. Got help from Udacity mentor for the additional materials.

## API Endpoints:

1. /catalog/JSON - view the list of catalog categories in JSON</br>
2. /catalog/cagegory_id/item/id/JSON - view the item for the particular
   category_id and item id in JSON</br>
3. /catalog/category_id/items -view the list of items for the particular
   category_id in JSON</br>
