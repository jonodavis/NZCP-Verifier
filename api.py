import verifier
from flask import Flask, request, jsonify

api = Flask(__name__)

@api.route('/verify', methods=['POST'])
def verify():
  try:
    req = request.get_json()
    res = jsonify(verifier.check_code(req["payload"]))
    res.headers.add('Access-Control-Allow-Origin', '*')
    return res
  except:
    res = jsonify({"validated": False})
    res.headers.add('Access-Control-Allow-Origin', '*')
    return {"validated": False} 

if __name__ == '__main__':
  api.run()