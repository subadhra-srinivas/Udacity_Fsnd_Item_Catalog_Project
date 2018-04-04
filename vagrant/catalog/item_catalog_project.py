from flask import (Flask, render_template, request, redirect, jsonify, url_for,
                   flash, abort)
from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Categories, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from sqlalchemy import desc
import logging

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///categoriesitem.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Put the log messages in the item_catalog.log 
logging.basicConfig(filename='item_catalog.log',level=logging.DEBUG)

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

# Function connecting to facebook page
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Get the access token
    access_token = request.data
    logging.debug("access token received %s " % access_token)
    # Exchange client token for long-lived server-side taken with GET
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type='
           'fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token'
           '=%s' % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    logging.debug(repr(result))

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first
        index which gives us the key : value for the server access token
        then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be
        used directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')
    token1 = result.split(',')[0].split(':')[1].replace('"', '')
    logging.debug(repr(token1))
    url = ('https://graph.facebook.com/v2.8/me?access_token=%s&fields='
           'name,id,email' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = ('https://graph.facebook.com/v2.8/me/picture?access_token=%s'
           '&redirect=0&height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    logging.debug(repr(data))
    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

# Function disconnecting from facebook page
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token'
           '=%s' % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# Function connecting to google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    # request.get_data()
    # code = request.data.decode('utf-8')
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session

# Function disconnect from google login
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

 

# JSON APIs to view Catalog Information
@app.route('/catalog/<int:category_id>/items/JSON')
def ItemCategoryJSON(category_id):
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON API's to view particular item for the category id specified
@app.route('/catalog/<int:category_id>/item/<int:id>/JSON')
def ItemJSON(category_id, id):
    item = session.query(Item).filter_by(id=id, category_id=category_id).one()
    return jsonify(Item=item.serialize)


# JSON API's to view the catalog information
@app.route('/catalog/JSON')
def CatalogJSON():
    catalog = session.query(Categories).all()
    return jsonify(Catalog=[i.serialize for i in catalog])

# Decorator for login_required
def login_required(func):
    @wraps(func) # this requires an import
    def wrapper(*args, **kwargs):
        logging.debug(kwargs)
        if 'username' not in login_session:
            return redirect('login')
        else:
            return func(*args, **kwargs)
    return wrapper

# Decorator for category_exists 
def category_exists(func):
      @wraps(func) # this requires an import
      def wrapper(*args, **kwargs):
             logging.debug(kwargs)
             category_id = kwargs['category_id']
             category = session.query(Categories).filter_by(id=category_id).one_or_none()
             if not category:
                 return abort(404)
             else:
                 return func(*args, **kwargs)
      return wrapper

# Decorator for item_category_exists 
def item_category_exists(func):
      @wraps(func) # this requires an import
      def wrapper(*args, **kwargs):
             logging.debug(kwargs)
             category_id = kwargs['category_id']
             id = kwargs['id']

             item = session.query(Item).filter_by(id=id, category_id=category_id).one_or_none()
             
             if not item:
                 return abort(404)
             else:
                 return func(*args, **kwargs)
      return wrapper

# Decorator for item_exits 
def item_exists(func):
      @wraps(func) # this requires an import
      def wrapper(*args, **kwargs):
             logging.debug(kwargs)
             id = kwargs['id']

             item = session.query(Item).filter_by(id=id).one_or_none()

             if not item:
                 return abort(404)
             else:
                 return func(*args, **kwargs)
      return wrapper


# Decorator for authetication_required 
def authentication_required(func):
      @wraps(func) # this requires an import
      def wrapper(*args, **kwargs):
             item = session.query(Item).filter_by(id=kwargs['id']).one()
             if login_session['user_id'] != item.user_id:
                 return ("<script>function myFunction() {alert('You are not "
                         "authorized to make changes to this item. Please "
                         "create your own category in order to edit/delete "
                         "items.');}</script><body "
                         "onload='myFunction()''>")
             else:
                 return func(*args, **kwargs)
      return wrapper



# Show current Categories along with the latest items added
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    catalog = session.query(Categories).order_by(asc(Categories.name))
    items = session.query(Item).order_by(desc(Item.id))
    if 'username' not in login_session:
        is_logged_in = 0
    else:
        is_logged_in = 1
   
    return render_template('catalog.html', catalog=catalog,
                            items=items, is_logged_in=is_logged_in)


# Show the items for the particular category id
@app.route('/catalog/<int:category_id>/items')
@category_exists
def showCatagoryItem(category_id):

    category = session.query(Categories).filter_by(id=category_id).one_or_none()
    catalog = session.query(Categories).order_by(asc(Categories.name))
    items = session.query(Item).filter_by(category_id=category_id)
    count_items = session.query(Item).filter_by(
                                         category_id=category_id).count()
    if 'username' not in login_session:
        is_logged_in = 0
    else:
        is_logged_in = 1

    return render_template('showCategoryItem.html',
                            catalog=catalog, items=items,
                            category_name=category.name,
                            count_items=count_items,
                            is_logged_in=is_logged_in)


# Show the item for the particular category id and item id
@app.route('/catalog/<int:category_id>/item/<int:id>')
@item_category_exists
def showItem(category_id, id):
    item = session.query(Item).filter_by(id=id, category_id=category_id).one()
    creator = getUserInfo(item.user_id)
    if ('username' not in login_session or
            creator.id != login_session['user_id']):

        is_logged_in = 0
    else:
        is_logged_in = 1

    return render_template('item.html', item=item, creator=creator,
                                        is_logged_in=is_logged_in)


# Create a new item
@app.route('/catalog/item/new/', methods=['GET', 'POST'])
@login_required
def newItem():
    categories = session.query(Categories).all()
    if request.method == 'POST':
        category1 = session.query(Categories).filter_by(
                                 name=request.form['category']).one_or_none()
        
        if not category1:
            abort(404)

        newItem = Item(title=request.form['title'],
                       description=request.form['description'],
                       price=request.form['price'],
                       category=request.form['category'],
                       category_id=category1.id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New %s Item Successfully Created' % (newItem.title))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newitem.html', categories=categories)


# Edit a item
@app.route('/catalog/item/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@item_exists
@authentication_required
def editItem(id):
    categories = session.query(Categories).all()
    editedItem = session.query(Item).filter_by(id=id).one_or_none()
    logging.debug(login_session['user_id'])
    logging.debug(editedItem.user_id)
    if request.method == 'POST':
        if request.form.get('title'):
            editedItem.title = request.form['title']
        if request.form.get('description'):
            editedItem.description = request.form['description']
        if request.form.get('price'):
            editedItem.price = request.form['price']
        if request.form.get('category'):
            editedItem.category = request.form['category']
            category1 = session.query(Categories).filter_by(
                                      name=editedItem.category).one_or_none()
            if not category1:
                abort(404)

            editedItem.category_id = category1.id

        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('edititem.html', categories=categories,
                               item=editedItem)


# Delete a item
@app.route('/catalog/item/<int:id>/delete', methods=['GET', 'POST'])
@login_required
@item_exists
@authentication_required
def deleteItem(id):
    itemToDelete = session.query(Item).filter_by(id=id).one_or_none()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteitem.html', item=itemToDelete)


# Disconnect the login
@app.route('/disconnect')
def disconnect():
    logging.debug("Inside disconnect")
    if 'provider' in login_session:
        logging.debug(login_session['provider'])
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
