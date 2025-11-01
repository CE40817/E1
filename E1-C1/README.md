# E1-C1 Challenge: Phishing Post Mortem Hard Mode

## Scenario

You must reconstruct a stealthy phishing theft from three artifacts. The email is not plain, the landing page builds fields dynamically, and the exfil is not JSON with friendly names.

## What you get

* `mail.eml` with a quoted-printable body and parameters
* `landing.html` and `landing.js` that define client behavior
* `web_access.log` with mixed traffic, including JSON bodies and believable decoys

## Your goals

* Recover the campaign id and nonce from the email
* From `landing.js`, derive the effective parameter names and the action path
* Identify the single POST that matches the derived names and expected token
* Decode the password based on the client code and write it to `flag.txt`
