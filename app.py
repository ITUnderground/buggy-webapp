"""
==============================================================================
 VULNERABLE-BY-DESIGN TRAINING APP  —  FOR LOCAL / LAB USE ONLY
==============================================================================

 This application contains INTENTIONAL security vulnerabilities for teaching
 and practice. It is the software equivalent of a crash-test dummy.

 !!  NEVER expose this to the public internet.
 !!  NEVER run it on a machine that holds real data.
 !!  Run it on localhost or inside an isolated lab network only.

 Each vulnerability below is marked with a  # [VULN]  tag and a short note on
 how to exploit it, so it can be used as a guided exercise.
"""

import os
import time
import pymysql
import pymysql.cursors
from jinja2 import DictLoader, ChoiceLoader
from flask import (
    Flask, request, session, redirect, url_for, render_template_string,
    make_response, Response,
)

app = Flask(__name__)
# [VULN] Hard-coded, guessable secret key -> session cookies can be forged.
app.secret_key = "dev-secret-key-123"

# [VULN] The app connects to MySQL as root with the weak default password.
# An over-privileged DB account means any SQL injection runs with full rights
# (read every database, etc.). Defaults target the 'db' service from
# docker-compose; override with env vars for a bare run against 127.0.0.1.
DB_CONFIG = dict(
    host=os.environ.get("DB_HOST", "127.0.0.1"),
    port=int(os.environ.get("DB_PORT", "3306")),
    user=os.environ.get("DB_USER", "root"),
    password=os.environ.get("DB_PASSWORD", "root"),
    database=os.environ.get("DB_NAME", "appdb"),
)


# --------------------------------------------------------------------------- #
#  Database setup
# --------------------------------------------------------------------------- #
def connect_db():
    # DictCursor so rows behave like the old sqlite3.Row (row["col"]).
    return pymysql.connect(
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        **DB_CONFIG,
    )


def connect_with_retry(tries=30, delay=2):
    # MySQL takes a few seconds to come up on first `docker compose up`.
    last = None
    for _ in range(tries):
        try:
            return connect_db()
        except pymysql.Error as e:
            last = e
            time.sleep(delay)
    raise last


def db():
    return connect_db()


def init_db():
    # Creates the app's own tables INSIDE appdb, alongside the seeded
    # customers/app_secrets loot. So cracking the DB (default creds) exposes
    # the app's plaintext user passwords too — the two vulns reinforce.
    statements = [
        "DROP TABLE IF EXISTS users",
        "DROP TABLE IF EXISTS comments",
        """CREATE TABLE users (
               id       INT AUTO_INCREMENT PRIMARY KEY,
               username VARCHAR(100),
               password VARCHAR(100),   -- [VULN] passwords stored in plaintext
               role     VARCHAR(20),
               email    VARCHAR(100),
               secret   VARCHAR(255)
           )""",
        """CREATE TABLE comments (
               id     INT AUTO_INCREMENT PRIMARY KEY,
               author VARCHAR(100),
               body   TEXT
           )""",
        # id 1 and 2 are the login accounts. id 3 is the IDOR prize: nobody
        # logs in as 'vip', but its record leaks through /api/profile.
        """INSERT INTO users (username, password, role, email, secret) VALUES
               ('user',  'S3cr3t_p4ssw0rd!',       'user',  'user@vulnlab.test',  'nothing interesting here'),
               ('admin', 'admin',     'admin', 'admin@vulnlab.test', 'recovery phrase: correct-horse-battery-staple'),
               ('vip',   'unused-never-login','user',  'vip@vulnlab.test',   'flag{broken_object_level_authorization}')""",
        "INSERT INTO comments (author, body) VALUES ('system', 'Welcome to the lab. Leave a comment below.')",
    ]
    con = connect_with_retry()
    with con.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)
    con.close()


# --------------------------------------------------------------------------- #
#  Templates (inline to keep everything in one file)
# --------------------------------------------------------------------------- #
BASE = """
<!doctype html><html><head><title>VulnLab</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
<script src="{{ url_for('static', filename='app.js') }}"></script>
</head><body>
<nav>
 <a href="{{ url_for('index') }}">Home</a>
 <a href="{{ url_for('login') }}">Login</a>
 <a href="{{ url_for('comments') }}">Comments</a>
</nav><hr>
{% block body %}{% endblock %}
<hr><p class="muted">Logged in as:
 {{ session.get('username','(nobody)') }} [{{ session.get('role','-') }}]
 {% if session.get('username') %}· <a href="{{ url_for('logout') }}">logout</a>{% endif %}
</p></body></html>
"""

INDEX = """{% extends 'base' %}{% block body %}
<!--
  TODO(dave): drop the debug banner before go-live. Staging build only.
  build: 2024-06-infra-rollout
  preview access token: flag{secrets_dont_belong_in_html_comments}
  [VULN] INFORMATION DISCLOSURE: a dev note left in the HTML leaks a secret
  to anyone who hits "view source". Comments ship to the client. This is a
  self-contained find — the leaked value isn't used anywhere else.
-->
<h1>VulnLab</h1>
<p>A deliberately insecure practice site. Explore the links above.</p>
{% if session.get('uid') %}
 <button onclick="loadProfile({{ session.get('uid') }})">View my profile</button>
 <pre id="profile" class="box"></pre>
{% else %}
 <p class="muted">Log in to view your profile.</p>
{% endif %}
<p class="muted">There may or may not be an admin area somewhere around here.</p>
{% endblock %}"""

LOGIN = """{% extends 'base' %}{% block body %}
<h1>Login</h1>
{% if error %}<p style="color:#c00">{{ error }}</p>{% endif %}
<form method="post">
 <input name="username" placeholder="username">
 <input name="password" type="password" placeholder="password">
 <button>Sign in</button>
</form>
{% endblock %}"""

COMMENTS = """{% extends 'base' %}{% block body %}
<h1>Comments</h1>
<form method="post">
 <input name="author" placeholder="your name">
 <textarea name="body" placeholder="your comment"></textarea>
 <button>Post</button>
</form>
{% for c in comments %}
 <div class="box"><b>{{ c['author']|safe }}</b><br>{{ c['body']|safe }}</div>
{% endfor %}
{% endblock %}"""

ADMIN = """{% extends 'base' %}{% block body %}
<h1>Admin panel</h1>
<p>Secret admin area. User table:</p>
{% for u in users %}
 <div class="box">{{ u['id'] }} · {{ u['username'] }} · {{ u['password'] }} · {{ u['role'] }}</div>
{% endfor %}
{% endblock %}"""


# Make the 'base' template resolvable by {% extends 'base' %}
app.jinja_loader = ChoiceLoader([app.jinja_loader, DictLoader({"base": BASE})])


def page(tpl, **kw):
    return render_template_string(tpl, **kw)


# --------------------------------------------------------------------------- #
#  Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return page(INDEX)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [VULN] SQL INJECTION — user input concatenated straight into the query.
        #   Bypass login with username:   ' OR '1'='1' --
        #   or target admin with:         admin' --
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        con = db()
        try:
            with con.cursor() as cur:
                cur.execute(query)  # raw string, no params -> injectable
                row = cur.fetchone()
        except pymysql.Error as e:
            # [VULN] leaking the DB error (and the raw query) aids the attacker
            con.close()
            return page(LOGIN, error="SQL error: %s | query: %s" % (e, query))
        finally:
            con.close()

        if row:
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["uid"] = row["id"]
            resp = make_response(redirect(url_for("index")))
            # The 'auth' cookie is the login marker: set here, removed on logout.
            # [VULN] It's just the user's id in plaintext — trivially forgeable
            # (set auth=2 to look like the admin), and it proves only WHO you
            # are, never WHAT you're allowed to read. See /api/profile.
            resp.set_cookie("auth", str(row["id"]))
            return resp
        error = "Invalid credentials"
    return page(LOGIN, error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("auth")  # remove the login marker
    return resp


@app.route("/comments", methods=["GET", "POST"])
def comments():
    con = db()
    with con.cursor() as cur:
        if request.method == "POST":
            # Input stored verbatim; rendered later with |safe -> [VULN] STORED XSS
            #   Try posting:   <script>alert(document.cookie)</script>
            cur.execute(
                "INSERT INTO comments (author, body) VALUES (%s, %s)",
                (request.form.get("author", "anon"), request.form.get("body", "")),
            )
        cur.execute("SELECT * FROM comments ORDER BY id DESC")
        rows = cur.fetchall()
    con.close()
    return page(COMMENTS, comments=rows)


# [VULN] HARD-CODED CREDENTIALS (CWE-798) + WEAK DEFAULTS.
#   The admin gate is a username/password baked straight into the source, and
#   they're the most guessable pair there is: admin / admin. Anyone who reads
#   the code (or just tries the obvious) is in. Credentials in source also leak
#   through version control, backups, and the /api/secrets endpoint style of
#   bug. Real auth uses a datastore, hashed secrets, and a constant-time check.
ADMIN_USER = "admin"
ADMIN_PASS = "admin"


def is_admin():
    # [VULN] plain == comparison is not constant-time (timing side channel),
    #   on top of the credentials being hard-coded and weak.
    auth = request.authorization
    return bool(auth) and auth.username == ADMIN_USER and auth.password == ADMIN_PASS


@app.route("/admin")
def admin():
    # Gated by HTTP Basic Auth against the hard-coded admin/admin above.
    #   Get in from a browser (it will prompt), or:
    #       curl -u admin:admin http://127.0.0.1:5000/admin
    #   Once in, the page dumps every user including plaintext passwords.
    if not is_admin():
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="VulnLab Admin"'},
        )
    con = db()
    with con.cursor() as cur:
        cur.execute("SELECT * FROM users")
        users = cur.fetchall()
    con.close()
    return page(ADMIN, users=users)


@app.route("/robots.txt")
def robots():
    # [VULN] INFORMATION DISCLOSURE via robots.txt.
    #   Disallow tells well-behaved crawlers to stay out of these paths — but
    #   the file is public, so it instead ADVERTISES the "hidden" admin panel
    #   AND the secrets endpoint to anyone (attackers read robots.txt first,
    #   not last). robots.txt is a politeness hint, never an access control;
    #   listing a sensitive path here points a flashlight straight at it.
    body = "User-agent: *\nDisallow: /admin\nDisallow: /api/secrets\n"
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    # Public pages only. The admin panel (and the API/robots endpoints) are
    # deliberately left out, as a real sitemap would omit a hidden panel.
    # Note: leaving /admin out of the sitemap is NOT a security control — the
    # page is still directly reachable, and robots.txt even names it.
    pages = ["index", "login", "comments"]
    urls = "\n".join(
        "  <url><loc>%s</loc></url>" % url_for(p, _external=True) for p in pages
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + urls
        + "\n</urlset>\n"
    )
    return Response(xml, mimetype="application/xml")


@app.route("/api/profile")
def api_profile():
    # [VULN] AUTHENTICATION WITHOUT AUTHORIZATION  (IDOR / Broken Object Level
    #        Authorization — OWASP API #1).
    #   The endpoint correctly checks that you are logged in: the 'auth' cookie
    #   must be present. That is AUTHENTICATION ("who are you?").
    #   It then returns whatever ?id= you ask for, WITHOUT checking that the id
    #   belongs to you. The missing AUTHORIZATION check ("are you allowed to
    #   read THIS record?") is the bug.
    #
    #   Exploit: log in as 'user' (id 1), then walk the ids:
    #       curl --cookie "auth=1" "http://127.0.0.1:5000/api/profile?id=3"
    #   -> leaks the 'vip' user (id 3) you were never meant to see.
    #
    #   Note: the query below is parameterized on purpose. The lesson here is
    #   the authorization gap, not SQL injection — keeping SQLi out keeps the
    #   exercise clean. The fix is to serve only the caller's own record, e.g.
    #       uid = request.cookies["auth"]        # ignore any ?id= from the user
    #   or to verify request id == session uid before returning the row.
    if not request.cookies.get("auth"):
        return {"error": "not authenticated"}, 401

    # Defaults to your own id (what the in-app button sends); an attacker
    # simply overrides ?id= to read someone else's record.
    uid = request.args.get("id", request.cookies.get("auth"))
    con = db()
    with con.cursor() as cur:
        cur.execute(
            "SELECT id, username, email, role, secret FROM users WHERE id = %s",
            (uid,),  # parameterized on purpose: the bug is missing authz, not SQLi
        )
        row = cur.fetchone()
    con.close()
    if not row:
        return {"error": "no such user"}, 404
    return {"user": dict(row)}


# --------------------------------------------------------------------------- #
#  API
# --------------------------------------------------------------------------- #
# All fabricated placeholders — not real credentials. They only need to *look*
# like the kind of secret that should never be exposed over an API.
FAKE_SECRETS = {
    "aws_access_key_id": "AKIAZ7EXAMPLE4TRAINING",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "database_url": "postgres://vulnlab:hunter2@db.internal:5432/app",
    "jwt_signing_secret": "super-secret-jwt-signing-key-do-not-share",
    "stripe_test_key": "sk_test_51Example0000FakeTrainingKey00000",
    "openai_api_key": "sk-proj-FAKEexample000TrainingToken000NOTreal000abcDEF",
    "internal_admin_token": "adm_8f3b2c9d-FAKE-TOKEN-training-only",
}


@app.route("/api/secrets")
def api_secrets():
    # [VULN] SENSITIVE DATA EXPOSURE — no authentication at all.
    #   The endpoint returns the secrets to anyone who requests it, straight
    #   from a browser:
    #       http://127.0.0.1:5000/api/secrets
    #   Combined with robots.txt (which names this path), it's a complete
    #   disclosure chain: read robots.txt -> hit the path -> dump the secrets.
    #   Fix: require real authentication, and don't serve secrets over an API
    #   endpoint like this in the first place.
    return {"secrets": FAKE_SECRETS}


if __name__ == "__main__":
    init_db()
    # Bare `python app.py` defaults to localhost. In Docker, HOST is set to
    # 0.0.0.0 so the container is reachable; exposure is controlled by binding
    # the published port to 127.0.0.1 on the host (see docker-compose.yml).
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    # debug=True also enables the Werkzeug debugger -> [VULN] RCE if reachable.
    app.run(host=host, port=port, debug=True)
