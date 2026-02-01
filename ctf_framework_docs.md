# SION-CTF Framework Notes

- Framework expects a Flask app in `app.py` listening on port 5000 with `/health` returning `OK`.
- Keep the `FLAG` variable intact; exploit must reveal it, safe request must not.
- Use modern Flask 3.x patterns (no `before_first_request`); run with `app.run(host="0.0.0.0", port=5000)`.
- Requirements are installed from `requirements.txt`; add any new packages there.
- Tests (via `verify_challenge.py`) perform two HTTP checks:
  1) Exploit request must return the flag.
  2) Safe request must not return the flag.

