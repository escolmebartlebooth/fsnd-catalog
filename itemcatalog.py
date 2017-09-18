"""
    catalogue application to show and allow maintenance of items
    created: 12-03-17
    created by: escolme
"""

# Imports flask
from flask import Flask, render_template, url_for
from flask import request, redirect, flash, jsonify
from flask import session as login_session
from flask import make_response

# imports database
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker, joinedload
from catalog_database_setup import Base, User, Category, Item

# imports general
from functools import wraps
import random
import string
import json
import requests
import time
import datetime

# imports oauth google
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

# imports oauth amazon
import pycurl
import urllib
import StringIO

# Application configuration
app = Flask(__name__)

# database configuration
dbstring = 'postgresql://catalog:catalog@localhost:5432/catalog'
engine = create_engine(dbstring)

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# oauth credential loading
GCLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

ACLIENT_ID = json.loads(
    open('amazon_secrets.json', 'r').read())['web']['client_id']

# database functions
def showCategories():
    """ return all categories """
    return session.query(Category).order_by(Category.name).all()


def showItems():
    """ return all items """
    return session.query(Item).order_by(desc(Item.updated)).all()


def showItemsByCategory(category_id):
    """ return all items in a category """
    return session.query(Item).filter_by(category_id=
                                         category_id).all()


def oneCategory(category_id):
    """ return a specific category """
    return session.query(Category).filter(Category.id ==
                                          category_id).one()


def ownsCategory(category_id, user_id):
    """ return category owned by a user """
    return session.query(Category).filter(Category.id ==
                                          category_id).filter(Category.user_id ==
                                          user_id).first()


def oneItem(item_id):
    """ return a specific item """
    return session.query(Item).filter(Item.id == item_id).one()


def ownsItem(item_id, user_id):
    """ return item owned by user"""
    return session.query(Item).filter(Item.id ==
                                      item_id).filter(Item.user_id ==
                                                      user_id).first()


# decorators
def loggedIn(func):
    """
        test whether user is logged in
        if not direct to login page
        if logged in proceed with function
    """
    @wraps(func)
    def wrap(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        else:
            return func(*args, **kwargs)
    return wrap

@app.template_filter('fdate')
def fdate(adate):
    """ filter to format a date on a template """
    return datetime.date.strftime(adate, "%d %m %Y at %H %M")


def generate_state():
    """ state token generator """
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


# user helpers
def createUser(login_session):
    """ create a new user and return its id """
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=
                                         login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ find and return a specific user """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """ see if a user exists by email """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def removeLoginDetails():
    """ helper to remove login details on logout """
    del login_session['credentials']
    del login_session['id']
    del login_session['provider']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']

# page handlers

@app.route('/')
@app.route('/categories/')
def listCategories():
    """
        render the home page passing the list of categories
        and items and whether the caller is logged in
    """
    return render_template('categories.html',
                           logged_in=('username' in login_session),
                           title="Categories",
                           categories=showCategories(),
                           items=showItems())


@app.route('/categories/<int:category_id>')
def categoryView(category_id):
    """
        render a view page for a specific category
        with the category's items
        test whether the category is owned by the user
        this allows the template to display edit and delete
    """
    category = oneCategory(category_id)
    items = showItemsByCategory(category_id)
    if ('username' in login_session):
        owns_category = ownsCategory(category_id,
                                     login_session['user_id'])
    else:
        owns_category = False

    return render_template('category.html',
                           logged_in=('username' in login_session),
                           owns_category=owns_category,
                           title="Category",
                           category=category,
                           items=items)


@app.route('/categories/new', methods=['GET', 'POST'])
@loggedIn
def categoryNew():
    """
        check the user is logged in
        and then render new category page
        otherwise redirect to login page
        use the logged in state to counter CSFR
    """
    if request.method != 'POST':
        return render_template('category_new.html',
                               logged_in=('username' in login_session),
                               title="New Category",
                               STATE=login_session['state'])
    else:
        if request.form['name'] == "":
            # the category name is blank re-render page with error
            return render_template('category_new.html',
                                   logged_in=('username' in login_session),
                                   title="New Category",
                                   error="Please Enter a Category",
                                   STATE=login_session['state'])
        else:
            if request.form['state'] != login_session['state']:
                flash("invalid state parameters %s" % login_session['email'])
            else:
                # create the new category
                newCategory = Category(name=request.form['name'],
                                       user_id=login_session['user_id'])
                session.add(newCategory)
                session.commit()
                flash('item created!')

            return redirect(url_for('listCategories'))


@app.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@loggedIn
def categoryEdit(category_id):
    """
        check the user is logged in - if not go to login
        and whether the user owns the category - if not show error
        and then render new category page
        use the logged in state to counter CSFR
    """

    if ownsCategory(category_id, login_session['user_id']):
        # owns the category
        category = oneCategory(category_id)
        if request.method != 'POST':
            return render_template('category_edit.html',
                                   logged_in=('username' in login_session),
                                   category=category,
                                   STATE=login_session['state'])
        else:
            if request.form['name'] == "":
                # if the category is blank, re-render form with error
                return render_template('category_edit.html',
                                       logged_in=('username' in login_session),
                                       title="Edit Category",
                                       error="Please Enter a Category",
                                       category=category,
                                       STATE=login_session['state'])
            else:
                if request.form['state'] != login_session['state']:
                    flash("invalid state parameters %s" % login_session['email'])
                else:
                    # update the category
                    category.name = request.form['name']
                    session.add(category)
                    session.commit()
                    flash('category updated!')

                return redirect(url_for('listCategories'))
    else:
        flash('you do not own this category!')
        return redirect(url_for('listCategories'))


@app.route('/categories/<int:category_id>/delete', methods=['GET', 'POST'])
@loggedIn
def categoryDelete(category_id):
    """
        check if logged in - if not redirect to login
        and owns the category - if not error
        then show the delete form
        use the logged in state to counter CSFR
    """
    if ownsCategory(category_id, login_session['user_id']):
        category = oneCategory(category_id)
        if request.method == 'POST':
            if (showItemsByCategory(category.id)):
                return render_template('category_delete.html',
                                   logged_in=('username' in login_session),
                                   title="Delete Category",
                                   category=category,
                                   error='Category has items',
                                   STATE=login_session['state'])
            else:
                if request.form['state'] != login_session['state']:
                    flash("invalid state parameters %s" % login_session['email'])
                else:
                    session.delete(category)
                    session.commit()
                    flash('category deleted!')
                return redirect(url_for('listCategories'))
        else:
            return render_template('category_delete.html',
                                   logged_in=('username' in login_session),
                                   title="Delete Category",
                                   category=category,
                                   STATE=login_session['state'])
    else:
        flash('you do not own this category!')
        return redirect(url_for('listCategories'))


@app.route('/categories/items/<int:item_id>')
def itemView(item_id):
    """
        render one item
        use the logged in state to counter CSFR
    """
    item = oneItem(item_id)
    if ('username' in login_session):
        owns_item = ownsItem(item_id, login_session['user_id'])
    else:
        owns_item = False

    return render_template('item.html',
                           logged_in=('username' in login_session),
                           owns_item=owns_item,
                           title="Item",
                           item=item)


@app.route('/categories/items/new', methods=['GET', 'POST'])
@loggedIn
def itemNew():
    """
        check logged in - if not show login page
        and then render new item page
        use the logged in state to counter CSFR
    """
    if request.method != 'POST':
        return render_template('item_new.html',
                               logged_in=('username' in login_session),
                               title="New Item",
                               categories=showCategories(),
                               STATE=login_session['state'])
    else:
        if request.form['name'] == "":
            # if the form is blank, show an error
            return render_template('item_new.html',
                                   logged_in=('username' in login_session),
                                   title="New Item",
                                   categories=showCategories(),
                                   error="Please Enter a Item",
                                   STATE=login_session['state'])
        else:
            if request.form['state'] != login_session['state']:
                flash("invalid state parameters %s" % login_session['email'])
            else:
                # otherwise save the new item
                newItem = Item(name=request.form['name'],
                               description=request.form['description'],
                               category_id=request.form['category'],
                               user_id=login_session['user_id'])
                session.add(newItem)
                session.commit()
                flash('item created!')
            return redirect(url_for('listCategories'))


@app.route('/categories/items/<int:item_id>/edit', methods=['GET', 'POST'])
@loggedIn
def itemEdit(item_id):
    """
        check logged in - if not go to login
        check owns item - if not error
        and then render new category page
    """
    if ownsItem(item_id, login_session['user_id']):
        item = oneItem(item_id)
        if request.method != 'POST':
            return render_template('item_edit.html',
                                   logged_in=('username' in login_session),
                                   title="Edit Item",
                                   item=item,
                                   categories=showCategories(),
                                   STATE=login_session['state'])
        else:
            if request.form['name'] == "":
                # if the item name is blank, show an error
                return render_template('item_edit.html',
                                       logged_in=('username' in login_session),
                                       title="Edit Item",
                                       error="Please Enter an Item",
                                       item=item, categories=showCategories(),
                                       STATE=login_session['state'])
            else:
                if request.form['state'] != login_session['state']:
                    flash("invalid state parameters %s" % login_session['email'])
                else:
                    # otherwise update the item
                    item.name = request.form['name']
                    item.description = request.form['description']
                    item.category_id = request.form['category']
                    session.add(item)
                    session.commit()
                    flash('item updated!')
                return redirect(url_for('listCategories'))
    else:
        flash('you do not own this item!')
        return redirect(url_for('listCategories'))


@app.route('/categories/items/<int:item_id>/delete', methods=['GET', 'POST'])
@loggedIn
def itemDelete(item_id):
    """ check if logged in - if not show login
        check if owns item - if not error
        show deletion page if all ok
        use the logged in state to counter CSFR
    """
    if ownsItem(item_id, login_session['user_id']):
        item = oneItem(item_id)
        if request.method == 'POST':
            if request.form['state'] != login_session['state']:
                flash("invalid state parameters %s" % login_session['email'])
            else:
                # delete the item
                session.delete(item)
                session.commit()
                flash('item deleted!')
            return redirect(url_for('listCategories'))
        else:
            return render_template('item_delete.html',
                                   logged_in=('username' in login_session),
                                   title="Delete Item",
                                   item=item,
                                   STATE=login_session['state'])
    else:
        flash('you do not own this item!')
        return redirect(url_for('listCategories'))


@app.route('/login')
def showLogin():
    """ create a state token and show the login page """
    login_session['state'] = generate_state()
    return render_template('login.html', STATE=login_session['state'])


@app.route('/aconnect', methods=['POST'])
def aconnect():
    """ section to allow amazon login
    """
    # check for CSRF
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    #code = request.data
    access_token = request.data #request.args.get('access_token')
    b = StringIO.StringIO()

    # verify that the access token belongs to us
    c = pycurl.Curl()
    c.setopt(pycurl.URL, "https://api.amazon.com/auth/o2/tokeninfo?access_token=" + urllib.quote_plus(access_token))
    c.setopt(pycurl.SSL_VERIFYPEER, 1)
    c.setopt(pycurl.WRITEFUNCTION, b.write)

    c.perform()
    d = json.loads(b.getvalue())

    if d['aud'] != ACLIENT_ID:
        # the access token does not belong to us
        response = make_response(
            json.dumps('code does not correlate with this site and user'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_a_id = login_session.get('user_id')
    if stored_credentials is not None and d['user_id'] == stored_a_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = d['aud']
    login_session['id'] = d['user_id']

    # exchange the access token for user profile
    b = StringIO.StringIO()

    c = pycurl.Curl()
    c.setopt(pycurl.URL, "https://api.amazon.com/user/profile")
    c.setopt(pycurl.HTTPHEADER, ["Authorization: bearer " + access_token])
    c.setopt(pycurl.SSL_VERIFYPEER, 1)
    c.setopt(pycurl.WRITEFUNCTION, b.write)

    c.perform()
    d = json.loads(b.getvalue())

    login_session['provider'] = "amazon"
    login_session['username'] = d['name']
    login_session['email'] = d['email']
    login_session['picture'] = ''

    # check if user exists...
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['email']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['email'])
    print "done!"
    return output


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ google login """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
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
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
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
    if result['issued_to'] != GCLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = "google"
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user exists...
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['email']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['email'])
    print "done!"
    return output


@loggedIn
def gdisconnect():
    """ disconnect from google """
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s' %
           login_session['credentials'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    return result['status'] == '200'


@app.route('/logout')
@loggedIn
def logout():
    """ logout of either google or amazon """
    access_token = login_session['credentials']
    if access_token is None:
        flash("Current user not connected.")
        return redirect(url_for('listCategories'))

    if (login_session['provider'] == 'google'):
        result = gdisconnect()
        removeLoginDetails()
    elif (login_session['provider'] == 'amazon'):
        removeLoginDetails()
        return render_template('logout.html')

    if result:
        flash("Successfully disconnected")
        return redirect(url_for('listCategories'))
    else:
        flash("Failed to revoke token for given user.")
        return redirect(url_for('listCategories'))


@app.route('/categories/JSON')
def categoriesJSON():
    """ output a JSON representation """
    categories = showCategories()

    serializedCategories = []
    for i in categories:
        new_category = i.serialize
        items = showItemsByCategory(i.id)
        serializedItems = []
        for j in items:
            serializedItems.append(j.serialize)
        new_category['items'] = serializedItems
        serializedCategories.append(new_category)

    return jsonify(Categories=serializedCategories)


# run the application
if __name__ == '__main__':
    app.secret_key = 'super_key'
    app.debug = True
    app.run(host='0.0.0.0', port=80)
