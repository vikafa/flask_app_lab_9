from flask import Flask, request, jsonify
from datetime import datetime
import hashlib
import secrets


app = Flask(__name__)
users = {}


def hash_password(password):
    salt = secrets.token_hex(16)

    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    hashed_password = hashlib.sha256(password_bytes + salt_bytes).hexdigest()

    return hashed_password, salt


@app.route('/user/register', methods=['POST'])
def register_user():
    data = request.json
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password are required.'}), 400

    username = data['username']
    password = data['password']

    if username in users:
        return jsonify({'error': 'Username already exists.'}), 400

    hashed_password, salt = hash_password(password)
    registration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    users[username] = {
        'hashed_password': hashed_password,
        'salt': salt,
        'registration_date': registration_date
    }

    return jsonify({'message': 'User registered successfully.'}), 201


if __name__ == '__main__':
    app.run(debug=True)
