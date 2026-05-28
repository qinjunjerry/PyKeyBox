#!/usr/bin/env python3

"""A minimal Flask web UI for the PyKeyBox password manager."""

import os
import secrets
import time

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)

from keybox import KeyBox, get_default_db_file

app = Flask(__name__)
app.secret_key = os.environ.get("KEYBOX_SECRET", secrets.token_hex(32))

DB_FILE = os.environ.get("KEYBOX_DB") or get_default_db_file()


@app.template_filter("datetime")
def _format_datetime(mod_time):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(mod_time)))

# Server-side store mapping a session id to the in-memory AES key, so the key
# is never placed in the (client-side) session cookie.
_aes_keys = {}


def open_box(require_key=True):
    box = KeyBox(DB_FILE)
    sid = session.get("sid")
    key = _aes_keys.get(sid) if sid else None
    if require_key:
        if key is None:
            return None
        box.aes_key = key
    return box


@app.before_request
def require_login():
    if request.endpoint in ("login", "static"):
        return
    if not session.get("sid") or session["sid"] not in _aes_keys:
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    box = KeyBox(DB_FILE)
    initialized = box.is_initialized()
    if request.method == "POST":
        password = request.form.get("password", "")
        if not password:
            flash("Password is required")
            return render_template("login.html", initialized=initialized)
        if initialized:
            if not box.check_master_password(password):
                flash("Incorrect master password")
                return render_template("login.html", initialized=initialized)
        else:
            if password != request.form.get("confirm", ""):
                flash("Passwords do not match")
                return render_template("login.html", initialized=initialized)
            box.set_master_password(password)
        sid = secrets.token_hex(32)
        _aes_keys[sid] = box.aes_key
        session["sid"] = sid
        return redirect(url_for("index"))
    return render_template("login.html", initialized=initialized)


@app.route("/logout")
def logout():
    sid = session.pop("sid", None)
    if sid:
        _aes_keys.pop(sid, None)
    return redirect(url_for("login"))


@app.route("/")
def index():
    box = open_box()
    q = request.args.get("q", "").strip()
    if q:
        items = box.search(q.split())
    else:
        items = box.list()
    return render_template("list.html", items=items, q=q)


@app.route("/view")
def view():
    title = request.args.get("title", "")
    box = open_box()
    if not box.exists(title):
        abort(404)
    mod_time, content = box.view(title)
    return render_template("view.html", title=title, content=content,
                           mod_time=mod_time)


@app.route("/add", methods=["GET", "POST"])
def add():
    box = open_box()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")
        if not title:
            flash("Title is required")
            return render_template("form.html", mode="add", title="",
                                   content=content)
        if box.exists(title):
            flash("A key with this title already exists")
            return render_template("form.html", mode="add", title=title,
                                   content=content)
        box.set(title, content, mod_time=time.time())
        return redirect(url_for("view", title=title))
    return render_template("form.html", mode="add", title="", content="")


@app.route("/edit", methods=["GET", "POST"])
def edit():
    title = request.args.get("title", "")
    box = open_box()
    if not box.exists(title):
        abort(404)
    if request.method == "POST":
        content = request.form.get("content", "")
        box.set(title, content, mod_time=time.time())
        return redirect(url_for("view", title=title))
    _, content = box.view(title)
    return render_template("form.html", mode="edit", title=title,
                           content=content)


@app.route("/delete", methods=["POST"])
def delete():
    title = request.form.get("title", "")
    box = open_box()
    if not box.exists(title):
        abort(404)
    box.delete(title)
    flash("Deleted '%s'" % title)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host=os.environ.get("KEYBOX_HOST", "127.0.0.1"),
            port=int(os.environ.get("KEYBOX_PORT", "5000")),
            debug=False)
