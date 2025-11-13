from flask import Flask, request, jsonify, render_template
from crypto_module import encrypt_bytes, decrypt_bytes

app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_api():
    data = request.json
    alg = data.get('alg', 'AES')
    mode = data.get('mode', 'CBC')
    key = data.get('key', '')
    plaintext = data.get('plaintext', '').encode('utf-8')
    res = encrypt_bytes(alg, mode, key.encode('utf-8'), plaintext)
    return jsonify(res)

@app.route('/decrypt', methods=['POST'])
def decrypt_api():
    data = request.json
    alg = data.get('alg', 'AES')
    mode = data.get('mode', 'CBC')
    key = data.get('key', '')
    payload = data.get('payload', {})
    try:
        pt = decrypt_bytes(alg, mode, key.encode('utf-8'),
                           payload['ciphertext'],
                           payload.get('iv'),
                           payload.get('nonce'),
                           payload.get('tag'))
        return jsonify({'plaintext': pt.decode('utf-8')})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
