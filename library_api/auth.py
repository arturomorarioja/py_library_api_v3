from flask import Blueprint, request, jsonify
from library_api.database import get_db
from library_api.utils import error_message
from library_api.common import user_by_token
import uuid

bp_auth = Blueprint('auth', __name__)

# Validate login information
@bp_auth.route('/auth/login', methods=['POST'])
def validate_user():
    email = request.form.get('email')
    password = request.form.get('password')

    if not (email and password):
        return error_message(), 400
    else:
        db = get_db()
        user = db.execute(
            '''
            SELECT 
                nMemberID AS user_id,
                bAdmin AS admin
            FROM tmember
            WHERE cEmail = ?
            AND cPassword = ?
            ''',
            (email, password)
        ).fetchone()
        if user == None:
            return error_message('Wrong credentials'), 401
        else:
            user_id = user['user_id']
            auth_token = str(uuid.uuid4());

            cursor = db.cursor()
            cursor.execute(
                '''
                UPDATE tmember
                SET cAuthToken = ?
                WHERE nMemberID = ?
                ''',
                (auth_token, user_id)
            )
            updated_rows = cursor.rowcount
            db.commit()
            cursor.close()

            if updated_rows == 0:
                return error_message('The authentication token could not be generated', 500)
            else:
                return jsonify({
                    'user_id': user_id,
                    'auth_token': auth_token,
                    'is_admin': user['admin']
                }), 200

# Logout
@bp_auth.route('/auth/logout', methods=['DELETE'])
def logout():
    user_id = user_by_token(request.headers.get('X-Session-Token'))
    if not user_id:
        return error_message('Invalid authentication token'), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        '''
        UPDATE tmember
        SET cAuthToken = ''
        WHERE nMemberID = ?
        ''',
        (user_id,)
    )
    updated_rows = cursor.rowcount
    db.commit()
    cursor.close()
    if updated_rows == 0:
        return error_message('The user could not be logged out'), 500
    
    return jsonify({'status': 'ok'}), 200