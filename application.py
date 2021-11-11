import verifier
from flask import Flask, request, jsonify
from flask_cors import CORS

application = Flask(__name__)
CORS(application)

@application.route('/verify', methods=['POST'])
def verify():
    try:
        req = request.get_json()
        res = jsonify(verifier.check_code(req["payload"]))
        return res
    except:
        res = jsonify({"verified": False})
        return {"verified": False} 

if __name__ == '__main__':
    application.run()