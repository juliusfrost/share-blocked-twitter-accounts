import os
import urllib.error
import urllib.parse
import urllib.request

import oauth2 as oauth
import twitter
from flask import Flask, render_template, request, url_for, session, redirect

app = Flask(__name__)

app.debug = False

request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'

# Support keys from environment vars (Heroku).
app.config['APP_CONSUMER_KEY'] = os.getenv(
    'TWAUTH_APP_CONSUMER_KEY', 'API_Key_from_Twitter')
app.config['APP_CONSUMER_SECRET'] = os.getenv(
    'TWAUTH_APP_CONSUMER_SECRET', 'API_Secret_from_Twitter')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'SECRET_KEY')

# alternatively, add your key and secret to config.cfg
# config.cfg should look like:
# APP_CONSUMER_KEY = 'API_Key_from_Twitter'
# APP_CONSUMER_SECRET = 'API_Secret_from_Twitter'
app.config.from_pyfile('config.cfg', silent=True)


@app.route('/')
def hello():
    if session.get('authenticated', False):
        return redirect(url_for('welcome'))
    return render_template('index.html')


@app.route('/start')
def start():
    # note that the external callback URL must be added to the whitelist on
    # the developer.twitter.com portal, inside the app settings
    app_callback_url = url_for('welcome', _external=True)

    # Generate the OAuth request tokens, then display them
    consumer = oauth.Consumer(
        app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    client = oauth.Client(consumer)
    resp, content = client.request(request_token_url, "POST", body=urllib.parse.urlencode({
        "oauth_callback": app_callback_url}))

    if resp['status'] != '200':
        error_message = 'Invalid response, status {status}, {message}'.format(
            status=resp['status'], message=content.decode('utf-8'))
        return render_template('error.html', error_message=error_message)

    request_token = dict(urllib.parse.parse_qsl(content))
    oauth_token = request_token[b'oauth_token'].decode('utf-8')
    oauth_token_secret = request_token[b'oauth_token_secret'].decode('utf-8')

    session[oauth_token] = oauth_token_secret
    redirect_url = authorize_url + '?oauth_token=' + oauth_token
    return redirect(redirect_url)


@app.route('/callback')
def callback():
    if session.get('authenticated', False):
        return redirect(url_for('welcome'))

    # Accept the callback params, get the token and call the API to
    # display the logged-in user's name and handle
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    oauth_denied = request.args.get('denied')

    # if the OAuth request was denied, delete our local token
    # and show an error message
    if oauth_denied:
        if oauth_denied in session:
            del session[oauth_denied]
        return render_template('error.html', error_message="the OAuth request was denied by this user")

    if not oauth_token or not oauth_verifier:
        return render_template('error.html', error_message="callback param(s) missing")

    # unless oauth_token is still stored locally, return error
    if oauth_token not in session:
        return render_template('error.html', error_message="oauth_token (" + oauth_token + ") not found locally")

    oauth_token_secret = session[oauth_token]

    # if we got this far, we have both callback params and we have
    # found this token locally

    consumer = oauth.Consumer(
        app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    token = oauth.Token(oauth_token, oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urllib.parse.parse_qsl(content))

    # These are the tokens you would store long term, someplace safe
    real_oauth_token = access_token[b'oauth_token'].decode('utf-8')
    real_oauth_token_secret = access_token[b'oauth_token_secret'].decode(
        'utf-8')

    # create python-twitter client
    session['authenticated'] = True
    session['oauth_token'] = real_oauth_token
    session['oauth_token_secret'] = real_oauth_token_secret

    del session[oauth_token]

    return redirect(url_for('welcome'))


@app.route('/welcome')
def welcome():
    if not session.get('authenticated', False):
        return render_template('error.html', error_message='Not authenticated yet!')
    twitter_api = twitter.Api(
        consumer_key=app.config['APP_CONSUMER_KEY'],
        consumer_secret=app.config['APP_CONSUMER_SECRET'],
        access_token_key=session['oauth_token'],
        access_token_secret=session['oauth_token_secret']
    )
    name = twitter_api.VerifyCredentials().name
    return render_template('welcome.html', name=name)


@app.route('/signout')
def signout():
    del session['oauth_token']
    del session['oauth_token_secret']
    session['authenticated'] = False
    return redirect('/')


@app.route('/export')
def export():
    if not session.get('authenticated', False):
        return render_template('error.html', error_message='Not authenticated yet!')
    twitter_api = twitter.Api(
        consumer_key=app.config['APP_CONSUMER_KEY'],
        consumer_secret=app.config['APP_CONSUMER_SECRET'],
        access_token_key=session['oauth_token'],
        access_token_secret=session['oauth_token_secret']
    )
    blocked_list = get_blocked_list(twitter_api)
    return render_template('export.html', blocked_list=blocked_list)


def get_blocked_list(twitter_api: twitter.Api):
    blocked_list = "id, screen_name,\n"
    for user in twitter_api.GetBlocks():
        blocked_list += str(user.id) + ', ' + user.screen_name + ',\n'
    return blocked_list


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message='uncaught exception'), 500


if __name__ == '__main__':
    app.run()
