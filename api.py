import verifier
from flask import Flask, request

api = Flask(__name__)

@api.route('/verify', methods=['POST'])
def verify():
  req = request.get_json()
  res = verifier.check_code(req["payload"])
  return res