from flask import *

from app import app

import models
import forms
from flask_oauth import OAuth

from flask.ext.login import current_user, LoginManager, login_user, login_required, logout_user

from flask_admin import Admin
from flask_admin.contrib.peewee import ModelView

from models import db
from pprint import pprint, pformat


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

FACEBOOK_APP_ID = '1037077632989343'
FACEBOOK_APP_SECRET = '99b3b23c3d55fa1269ddb5e8b9fce4d3'

oauth = OAuth()

facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email,public_profile'}
)

@facebook.tokengetter
def get_facebook_token():
    return session.get('facebook_token')

def pop_login_session():
    session.pop('logged_in', None)
    session.pop('facebook_token', None)
    session.pop('fbdata', None)

@login_manager.user_loader
def load_user(user_id):
    return models.User.get(id=user_id)


admin = Admin(app, name='littlebro', template_mode='bootstrap3', url="/admin")
admin.add_view(ModelView(models.User, db))

#----------------------------------------------------------------------------#
# Decorators.
#----------------------------------------------------------------------------#

@app.before_request
def before_request():
    g.db = db
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#




@app.route('/')
def home():
    return render_template('pages/placeholder.home.html')


@app.route('/about')
def about():
    return render_template('pages/placeholder.about.html')


@app.route('/authorize_fb', methods=['GET'])
@facebook.authorized_handler
def auth_fb(resp=None):
    next_url = request.args.get('next') or url_for('home')

    if resp is None or 'access_token' not in resp:
        flash('Facebook authentication failed. Please contact support', 'danger')
        return redirect(home)

    session['logged_in'] = True
    session['facebook_token'] = (resp['access_token'], '')


    fbdata = facebook.get('/me').data
    session['fbdata'] = fbdata
    # sometimes all we get is name and ID (long number)

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(', ')[-1]
    user, created = models.User.get_or_create(models.User.fbid == fbdata['id'],
                                                defaults={'signup_ip': ip_address, 'fbid': fbdata['id']}
                                                )
    login_user(user, remember=True)
    current_user.sync_details_from_fb(fbdata)
    if current_user.has_finished_registration:
        flash('you have been logged in!', 'success')
        return redirect(next_url)

    flash('Let\'s finish setting up your profile!', 'success')
    return redirect(url_for('update_profile'))


@app.route('/update_profile', methods=['GET','POST'])
def update_profile():
    next_url = request.args.get('next') or url_for('home')

    if 'fbdata' not in session:
        flash('There was a technical issue. Sorry', 'danger')

    form = forms.ProfileForm(request.form)

    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                models.User.get(models.User.email == form.data['email'])
                flash('An account with that email address already exists', 'danger')
            except:
                user = models.User.create(email = form.data['email'],
                                   )
                user.set_password(form.data['password'])
                if 'name' in session['fbdata']:
                    user.name = session['fbdata']['name']
                    user.save()
                login_user(user, remember=True)
                flash('Your account was created. You are now logged in.', 'success')
                return redirect(request.args.get('next') or url_for('home'))

    return render_template('forms/update_profile.html', form=form, fbdata=session['fbdata'])


@app.route('/forgot')
def forgot():
    form = forms.ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    pop_login_session() # logout facebook session
    flash("You have been logged out. Thanks!")
    return redirect( url_for('home') )


@app.route('/login', methods=['GET', 'POST'])
def login_with_facebook():
    return facebook.authorize(callback=url_for('auth_fb',
        next=request.args.get('next'), _external=True))




#----------------------------------------------------------------------------#
# Errors
#----------------------------------------------------------------------------#

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')



#----------------------------------------------------------------------------#
# API
#----------------------------------------------------------------------------#

@app.route('/api/v1/setkey', methods=['POST'])
def set_key(uid, pubkey):
    # user must be authenticated
    fbid = request.args.get('fbid') or abort(404)
    pw = request.args.get('auth') or abort(404)
    pubkey = request.args.get('pubkey') or abort(404)

    u = models.User.get(fbid=fbid)
    if u.check_password(pw):
        u.pubkey = pubkey
        u.save()
    else:
        return jsonify({'error': 'incorrect password. could not set your pubkey.'})

@app.route('/api/v1/getkey/<fbid>', methods=['GET'])
def get_key(fbid):
    #
    # Accepts fb id and returns public key.
    #
    fbid = request.args.get('fbid')
    try:
        u = models.User.get(models.User.fbid==fbid)
        return jsonify(u.pubkey)
    except models.User.DoesNotExist:
        return jsonify({'error': 'fbid not found.'})
