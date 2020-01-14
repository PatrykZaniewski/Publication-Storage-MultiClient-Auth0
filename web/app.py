from flask import Flask
from flask import request
from flask import make_response
from flask import Response
from flask import render_template
from flask import session as se
from dotenv import load_dotenv, find_dotenv
from flask import jsonify
from flask import redirect
from flask import url_for
from os import getenv
import datetime
import redisHandler
import sessionHandler
import redis
import jwt
import requests
import json
from functools import wraps
from os import environ as env
from werkzeug.exceptions import HTTPException
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode

load_dotenv(verbose=True)

app = Flask(__name__, static_url_path="/static")

app.secret_key = "super secret key"
oauth = OAuth(app)
SESSION_TIME = int(getenv("SESSION_TIME"))
JWT_SESSION_TIME = int(getenv('JWT_SESSION_TIME'))
JWT_SECRET = getenv("JWT_SECRET")
INVALIDATE = -1

AUTH0_CALLBACK_URL = getenv("AUTH0_CALLBACK_URL")
AUTH0_CLIENT_ID = getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = getenv("AUTH0_DOMAIN")
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = getenv("AUTH0_AUDIENCE")

redis = redis.Redis(host="redis", port="6379", decode_responses=True)
redisConn = redisHandler.RedisHandler(redis)
redisConn.initUser()

session = sessionHandler.SessionHandler(redis)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


@app.route('/callbackAuth0')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    se['jwt_payload'] = userinfo
    se['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name']
    }
    return redirect('/')


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in se:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


@app.route('/')
def index():
    if 'profile' not in se:
        return redirect('/login')
    return redirect("/index")


@app.route('/login', methods=['GET'])
def login():
    if 'profile' in se:
        return redirect('/index')
    return render_template("login.html")


@app.route('/auth', methods=['POST'])
def auth():
    return auth0.authorize_redirect(redirect_uri="https://web.company.com/callbackAuth0", audience=AUTH0_AUDIENCE)


@app.route('/index')
@requires_auth
def welcome():
    err = se.get('err')
    se['err'] = ''
    message = createFileMessage(err)
    uid = se['profile']['name']
    listToken = createListToken(uid).decode('utf-8')
    listOfPublications = json.loads(requests.get("http://cdn:5000/list/" + uid + "?token=" + listToken).content)
    return render_template("index.html", uid=uid, listToken=listToken, listOfPublications=listOfPublications,
                           message=message)

@app.route('/logout')
@requires_auth
def logout():
    se.clear()
    params = {'returnTo': 'https://web.company.com/login', 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/details')
@requires_auth
def detailsPublication():
    uid = request.args.get('uid')
    pid = request.args.get('pid')
    token = request.args.get('token')

    req = requests.get("http://cdn:5000/list/" + uid + "/" + pid + "?token=" + token)
    if req.status_code != requests.codes.ok:
        return redirectCallback(req.text)
    detailData = json.loads(req.content)
    downloadToken = createDownloadToken(uid).decode('utf-8')
    deleteToken = createDeleteToken(uid).decode('utf-8')
    uploadToken = createUploadToken(uid).decode('utf-8')
    listToken = createListToken(uid).decode('utf-8')
    publication = detailData.get('details')
    files = detailData.get('files')
    return render_template("details.html", uid=uid, downloadToken=downloadToken, deleteToken=deleteToken,
                           listToken=listToken, uploadToken=uploadToken,
                           publication=json.loads(publication), files=json.loads(files))


@app.route('/edit')
@requires_auth
def editPublication():
    uid = request.args.get('uid')
    pid = request.args.get('pid')
    token = request.args.get('token')
    req = requests.get("http://cdn:5000/list/" + uid + "/" + pid + "?token=" + token)
    if req.status_code != requests.codes.ok:
        return redirectCallback(req.text)
    detailData = json.loads(req.content)
    editToken = createEditToken(uid).decode('utf-8')
    publication = detailData.get('details')
    return render_template("edit.html", uid=uid, editToken=editToken, pid=pid,
                           publication=json.loads(publication))


@app.route('/editpublication', methods=['POST'])
@requires_auth
def editPublicationExecutive():
    token = request.form.get('token')
    author = request.form.get('author')
    publisher = request.form.get('publisher')
    title = request.form.get('title')
    date = request.form.get('publishDate')
    pid = request.form.get('pid')
    uid = request.form.get('uid')

    objToSend = {'author': author, 'publisher': publisher, 'title': title, 'publishDate': date, 'uid': uid,
                 'token': token}

    req = requests.post("http://cdn:5000/updlist/" + uid + "/" + pid, data=objToSend)

    return redirectCallback(req.text)


@app.route('/add')
@requires_auth
def addPublication():
    uid = se['profile']['name']
    uploadToken = createUploadToken(uid).decode('utf-8')
    return render_template("add.html", uid=uid, uploadToken=uploadToken)


@app.route('/addfiles', methods=['POST'])
@requires_auth
def addFilesExecutive():
    token = request.form.get('token')
    uid = request.form.get('uid')
    pid = request.form.get('pid')
    files = request.files.getlist('files')

    files = [('files', (f.filename, f.read())) for f in files]

    req = requests.post("http://cdn:5000/files/" + uid + "/" + pid + "?token=" + token, files=files)
    return redirectCallback(req.text)


@app.route('/stream')
@requires_auth
def stream():
    name = se['profile']['name']
    def event_stream(name):
        pubsub = redis.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(name)
        for message in pubsub.listen():
            return 'data: %s\n\n' % message['data']
    return Response(event_stream(name), mimetype="text/event-stream")


@app.route('/addpublication', methods=['POST'])
@requires_auth
def addPubExecutive():
    token = request.form.get('token')
    author = request.form.get('author')
    publisher = request.form.get('publisher')
    title = request.form.get('title')
    date = request.form.get('publishDate')
    uid = request.form.get('uid')
    files = request.files.getlist('files')

    objToSend = {'author': author, 'publisher': publisher, 'title': title, 'publishDate': date, 'uid': uid,
                 'token': token}
    files = [('files', (f.filename, f.read())) for f in files]

    req = requests.post("http://cdn:5000/list", data=objToSend, files=files)
    return redirectCallback(req.text)


@app.route('/deletepublication', methods=['POST'])
@requires_auth
def delPubExecutive():
    token = request.form.get('token')
    uid = request.form.get('uid')
    pid = request.form.get('pid')

    req = requests.post("http://cdn:5000/dellist/" + uid + "/" + pid + "?token=" + token)
    return redirectCallback(req.text)


@app.route('/deletefile', methods=['POST'])
@requires_auth
def delFileExecutive():
    token = request.form.get('token')
    uid = request.form.get('uid')
    pid = request.form.get('pid')
    filename = request.form.get('filename')

    req = requests.post("http://cdn:5000/delfiles/" + uid + "/" + pid + "?token=" + token + "&filename=" + filename)
    return redirectCallback(req.text)


def redirectCallback(error):
    response = make_response("", 303)
    response.headers["Location"] = "https://web.company.com/callback?error=" + error
    response.headers["Content-Type"] = "multipart/form-data"
    return response


@app.route('/callback')
@requires_auth
def callback():
    err = request.args.get('error')
    se['err'] = err
    return redirect('/login')


def createDownloadToken(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
    return jwt.encode({"iss": "web.company.com", "exp": exp, "uid": uid, "action": "download"}, JWT_SECRET, "HS256")


def createUploadToken(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
    return jwt.encode({"iss": "web.company.com", "exp": exp, "uid": uid, "action": "upload"}, JWT_SECRET, "HS256")


def createListToken(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
    return jwt.encode({"iss": "web.company.com", "exp": exp, "uid": uid, "action": "list"}, JWT_SECRET, "HS256")


def createDeleteToken(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
    return jwt.encode({"iss": "web.company.com", "exp": exp, "uid": uid, "action": "delete"}, JWT_SECRET, "HS256")


def createEditToken(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
    return jwt.encode({"iss": "web.company.com", "exp": exp, "uid": uid, "action": "edit"}, JWT_SECRET, "HS256")


def redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response


def createFileMessage(err):
    message = ''
    if err == "fileNotFound":
        message = f'<div class="error">Wybrany plik nie istnieje!</div>'
    elif err == "noCredentials":
        message = f'<div class="error">Nieprawidłowe dane użytkownika/publikacji!</div>'
    elif err == "noTokenProvided":
        message = f'<div class="error">Brak tokenu - odśwież stronę!</div>'
    elif err == "invalidToken":
        message = f'<div class="error">Token nieprawidłowy lub ważność wygasła!</div>'
    elif err == "invalidTokenPayload":
        message = f'<div class="error">Niezgodność tokenu z użytkownikiem i/lub akcją!</div>'
    elif err == "deletedPublication":
        message = f'<div class="info">Publikację usunięto!</div>'
    elif err == "uploadedPublication":
        message = f'<div class="info">Publikację dodano!</div>'
    elif err == "uploadedFile":
        message = f'<div class="info">Plik dodano do publikacji!</div>'
    elif err == "updatedPublication":
        message = f'<div class="info">Publikacja zaktualizowana!</div>'
    elif err == "deletedFile":
        message = f'<div class="info">Plik usunięto!</div>'
    return message
