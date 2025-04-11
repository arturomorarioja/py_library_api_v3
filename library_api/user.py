import re
from datetime import date, timedelta
from flask import Blueprint, request, jsonify, Response
from library_api.database import get_db
from library_api.utils import error_message
from library_api.common import basic_book_info, token_is_valid

bp_user = Blueprint('user', __name__)

# Return basic book info by ID 
@bp_user.route('/books/<int:book_id>', methods=['GET'])
def get_book(book_id: int):
    book_info = basic_book_info(book_id)

    # If the return value is a Response object, 
    # it comes from error_message()
    if isinstance(book_info, Response):
        return book_info, 404
    else:
        return jsonify(book_info), 200

# Return information for a random number of books,
# or search for books whose title contains a specific text,
# or search for books by a specific author
@bp_user.route('/books', methods=['GET'])
def get_random_books():
    number = request.args.get('n')
    search_text = request.args.get('s')
    author_id = request.args.get('a')
    if not (number or search_text or author_id):
        return error_message()
    else:
        db = get_db()
        sql = '''
            SELECT tbook.nBookID AS book_id, tbook.cTitle AS title, tbook.nPublishingYear AS publishing_year,
                trim(tauthor.cName || ' ' || tauthor.cSurname) AS author, tpublishingcompany.cName AS publishing_company
            FROM tbook INNER JOIN tauthor
                    ON tbook.nAuthorID = tauthor.nAuthorID
                INNER JOIN tpublishingcompany
                    ON tbook.nPublishingCompanyID = tpublishingcompany.nPublishingCompanyID
        '''
        # Random books retrieval
        if number is not None:
            sql += '''
                ORDER BY RANDOM()
                LIMIT ?
            '''
            books = db.execute(sql, (number,)).fetchall()
        # Book search
        elif search_text is not None:
            sql += '''
                WHERE tbook.cTitle LIKE ?
                ORDER BY tbook.cTitle
            '''
            books = db.execute(sql, (f'%{search_text}%',)).fetchall()
        # Retrieval of books by author
        else:
            sql += '''
                WHERE tbook.nAuthorID = ?
                ORDER BY tbook.cTitle
            '''
            books = db.execute(sql, (author_id,)).fetchall()

        book_list = [{key: book[key] for key in book.keys()} for book in books]
        return jsonify(book_list), 200   

# Return all authors
@bp_user.route('/authors', methods=['GET'])
def get_authors():
    db = get_db()
    authors = db.execute(
        '''
        SELECT nAuthorID AS author_id, trim(cName || ' ' || cSurname) AS author_name
        FROM tauthor
        ORDER BY cSurname, cName
        '''
    ).fetchall()

    author_list = [{key: author[key] for key in author.keys()} for author in authors]
    return jsonify(author_list), 200

# Return all publishing companies
@bp_user.route('/publishers', methods=['GET'])
def get_publishers():
    db = get_db()
    publishers = db.execute(
        '''
        SELECT nPublishingCompanyID AS publisher_id, cName AS publisher_name
        FROM tpublishingcompany
        ORDER BY cName
        '''
    ).fetchall()

    publisher_list = [{key: publisher[key] for key in publisher.keys()} for publisher in publishers]
    return jsonify(publisher_list), 200
               
# Return information for a specific user
@bp_user.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id: int):
    auth_token = request.headers.get('X-Session-Token');
    if not auth_token:
        return error_message('Non-existing authentication token'), 401
    
    db = get_db()
    user = db.execute(
        '''
        SELECT cEmail AS email, cName AS first_name, cSurname AS last_name, 
            cAddress AS address, cPhoneNo AS phone_number, 
            dBirth AS birth_date, dNewMember AS membership_date
        FROM tmember
        WHERE nMemberID = ?
        AND cAuthToken = ?
        ''',
        (user_id, auth_token)
    ).fetchone()

    if user == None:
        return error_message('User not found or wrong authentication token'), 404

    user_info = {key: user[key] for key in user.keys()}
    user_info['birth_date'] = str(user_info['birth_date'])
    user_info['membership_date'] = str(user_info['membership_date'])
    return jsonify(user_info), 200

# Add new user
@bp_user.route('/users', methods=['POST'])
def post_user():
    email = request.form.get('email')
    password = request.form.get('password')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    address = request.form.get('address')
    phone_number = request.form.get('phone_number')
    birth_date = request.form.get('birth_date')

    # All values are mandatory
    if not (email and password and first_name and last_name and address and phone_number and birth_date):
        return error_message(), 400
    else:
        # The password must be at least 8 characters long and include at least 
        # one uppercase and lowercase letter, one number and one special character.
        # RegEx pattern from https://uibakery.io/regex-library/password-regex-python
        if re.match('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$', password) == None:
            return error_message('Incorrect password format'), 400
        else:
            # The email address must not exist in the database
            db = get_db()
            user = db.execute(
                '''
                SELECT COUNT(*) AS total
                FROM tmember
                WHERE cEmail = ?
                ''',
                (email,)
            ).fetchone()
            if user['total'] > 0:
                return error_message('The user already exists'), 400
            else:
                cursor = db.cursor()
                cursor.execute(
                    '''
                    INSERT INTO tmember
                        (cEmail, cPassword, cName, cSurname, cAddress, cPhoneNo, dBirth, dNewMember, bAdmin)
                    VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (email, password, first_name, last_name, address, phone_number, birth_date, str(date.today()), 0)
                )
                user_id = cursor.lastrowid
                cursor.close()
                db.commit()

                return jsonify({'user_id': user_id}), 201

# Update a specific user
@bp_user.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id: int):
    auth_token = request.headers.get('X-Session-Token');
    if not auth_token:
        return error_message('Missing authentication token'), 401

    if not token_is_valid(user_id, auth_token):
        return error_message('Invalid authentication token'), 401
    
    fields = {
        'cEmail': request.form.get('email'),
        'cName': request.form.get('first_name'),
        'cSurname': request.form.get('last_name'),
        'cAddress': request.form.get('address'),
        'cPhoneNo': request.form.get('phone_number'),
        'dBirth': request.form.get('birth_date')
    }
    fields = { key: value for key, value in fields.items() if value is not None }

    if not fields:
        return error_message(), 400
    else:
        sql = 'UPDATE tmember SET ' + ', '.join([f'{key} = ?' for key in fields.keys()]) + ' WHERE nMemberID = ?'

        print(sql)
        print(list(fields.values()) + [user_id])

        db = get_db()
        cursor = db.cursor()
        cursor.execute(sql, list(fields.values()) + [user_id])
        updated_rows = cursor.rowcount
        db.commit()
        cursor.close()
        if updated_rows == 0:
            return error_message('The user could not be updated'), 500
        else:
            return jsonify({'status': 'ok'}), 200
        
# Delete a specific user
@bp_user.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id: int):
    auth_token = request.headers.get('X-Session-Token');
    if not auth_token:
        return error_message('Missing authentication token'), 401

    if not token_is_valid(user_id, auth_token):
        return error_message('Invalid authentication token'), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        '''
        DELETE FROM tloan
        WHERE nMemberID = ?
        ''',
        (user_id,)
    )

    cursor.execute(
        '''
        DELETE FROM tmember
        WHERE nMemberID = ?
        ''',
        (user_id,)
    )
    deleted_rows = cursor.rowcount
    db.commit()
    cursor.close()
    if deleted_rows == 0:
        return error_message('The user could not be deleted'), 500
    
    return jsonify({'status': 'ok'}), 200

# Loan a book
@bp_user.route('/users/<int:user_id>/books/<int:book_id>', methods=['POST'])
def loan_book(user_id: int, book_id: int):  
    auth_token = request.headers.get('X-Session-Token');
    if not auth_token:
        return error_message('Missing authentication token'), 401

    if not token_is_valid(user_id, auth_token):
        return error_message('Invalid authentication token'), 401
    
    # Check that the book is not already on loan by this user
    db = get_db()
    loan = db.execute(
        '''
        SELECT MAX(dLoan) AS last_loan_date
        FROM tloan
        WHERE nBookID = ?
        AND nMemberID = ?
        ''',
        (book_id, user_id)
    ).fetchone()

    today = date.today()
    if loan is not None:
        last_loan_date = loan['last_loan_date']
        if last_loan_date is not None:
            if loan['last_loan_date'] >= str(today - timedelta(days = 30)):
                return error_message('This user has still this book on loan'), 400
    
    # Loan the book
    cursor = db.cursor()
    cursor.execute(
        '''
        INSERT INTO tloan
            (nBookID, nMemberID, dLoan)
        VALUES
            (?, ?, ?)
        ''',
        (book_id, user_id, today)
    )
    inserted_rows = cursor.rowcount
    db.commit()
    cursor.close()
    if inserted_rows == 0:
        return error_message('It was not possible to loan the book'), 500
    else:
        return jsonify({'status': 'ok'})