#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

# activate the virtual environment
activate_this = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                             'venv/bin/activate_this.py')
with open(activate_this) as f:
    code = compile(f.read(), activate_this, 'exec')
    exec(code, dict(__file__=activate_this))


from flask import Flask, send_from_directory, abort

VECTOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors')


def main():
    app = Flask(__name__, static_folder=None, template_folder=None)

    @app.route('/<path:path>')
    def static(path):
        if '/keys/' in path:
            return abort(404)
        return send_from_directory(VECTOR_DIR, path)

    app.run(host='127.0.0.1', port=8080, debug=True)

if __name__ == '__main__':
    main()
