from datetime import date
from flask import Blueprint, request, jsonify, Response
from library_api.database import get_db
from library_api.utils import error_message
from library_api.common import basic_book_info

bp_admin = Blueprint('admin', __name__)
  
# Return detailed book info by ID 
@bp_admin.route('/books/<int:book_id>', methods=['GET'])
def get_detailed_book(book_id: int):
    db = get_db()
    book_info = basic_book_info(book_id)

    # If the return value is a Response object, 
    # it comes from error_message()
    if isinstance(book_info, Response):
        return book_info, 404
    else:
        loans = db.execute(
            '''
            SELECT nMemberID AS user_id, dLoan AS loan_date
            FROM tloan
            WHERE nBookID = ?
            ORDER BY dLoan
            ''',
            (book_id,)
        ).fetchall()

        # The loan date is converted to a string, but the user ID is not
        loan_list = [{key: str(loan[key]) if key == 'loan_date' else loan[key] \
            for key in loan.keys()} for loan in loans]
        book_info['loans'] = loan_list
        return jsonify(book_info), 200

# Add new book
@bp_admin.route('/books', methods=['POST'])
def post_book():
    title = request.form.get('title')
    author_id = request.form.get('author_id')
    publisher_id = request.form.get('publisher_id')
    publishing_year = int(request.form.get('publishing_year'))

    if not (title and author_id and publisher_id and publishing_year):
        return error_message(), 400
    else:
        db = get_db()
        author = db.execute(
            '''
            SELECT COUNT(*) AS Total
            FROM tauthor
            WHERE nAuthorID = ?
            ''',
            (author_id,)
        ).fetchone()

        if author['Total'] == 0:
            return error_message('The author does not exist'), 404
        else:
            if publishing_year > date.today().year:
                return error_message('Invalid year of publication'), 400
            else:
                publisher = db.execute(
                    '''
                    SELECT COUNT(*) AS Total
                    FROM tpublishingcompany
                    WHERE nPublishingCompanyID = ?
                    ''',
                    (publisher_id,)
                ).fetchone()

                if publisher['Total'] == 0:
                    return error_message('The publishing company does not exist'), 404
                else:
                    book = db.execute(
                        '''
                        SELECT COUNT(*) AS Total
                        FROM tbook
                        WHERE cTitle = ?
                        AND nAuthorID = ?
                        AND nPublishingYear = ?
                        AND nPublishingCompanyID = ?
                        ''',
                        (title, author_id, publishing_year, publisher_id)
                    ).fetchone()

                    if book['Total'] > 0:
                        return error_message('The book already exists'), 400
                    else:
                        cursor = db.cursor()
                        cursor.execute(
                            '''
                            INSERT INTO tbook
                                (cTitle, nAuthorID, nPublishingYear, nPublishingCompanyID)
                            VALUES
                                (?, ?, ?, ?)
                            ''',
                            (title, author_id, publishing_year, publisher_id)
                        )
                        book_id = cursor.lastrowid
                        inserted_rows = cursor.rowcount
                        db.commit()
                        cursor.close()

                        if inserted_rows == 0:
                            return error_message('There was an error when trying to insert the book'), 500
                        else:
                            return jsonify({'book_id': book_id}), 201

# Add new author
@bp_admin.route('/authors', methods=['POST'])
def post_author():
    first_name = request.form.get('first_name').strip()
    last_name = request.form.get('last_name').strip()

    if not (first_name and last_name):
        return error_message(), 400
    else:
        db = get_db()
        author = db.execute(
            '''
            SELECT COUNT(*) AS Total
            FROM tauthor
            WHERE cName = ? AND cSurname = ?
            ''',
            (first_name, last_name)
        ).fetchone()

        if author['Total'] > 0:
            return error_message('The author already exists'), 400
        else:            
            cursor = db.cursor()
            cursor.execute(
                '''
                INSERT INTO tauthor
                    (cName, cSurname)
                VALUES
                    (?, ?)
                ''',
                (first_name, last_name)
            )
            author_id = cursor.lastrowid
            inserted_rows = cursor.rowcount
            db.commit()
            cursor.close()

            if inserted_rows == 0:
                return error_message('There was an error while trying to insert the author'), 500
            else:
                return jsonify({'author_id': author_id}), 201

# Add new publishing company
@bp_admin.route('/publishers', methods=['POST'])
def post_publisher():
    name = request.form.get('name').strip()

    if not name:
        return error_message(), 400
    else:
        db = get_db()
        publisher = db.execute(
            '''
            SELECT COUNT(*) AS Total
            FROM tpublishingcompany
            WHERE cName = ?
            ''',
            (name,)
        ).fetchone()

        if publisher['Total'] > 0:
            return error_message('The publisher already exists'), 400
        else:            
            cursor = db.cursor()
            cursor.execute(
                '''
                INSERT INTO tpublishingcompany
                    (cName)
                VALUES
                    (?)
                ''',
                (name,)
            )
            publisher_id = cursor.lastrowid
            inserted_rows = cursor.rowcount
            db.commit()
            cursor.close()

            if inserted_rows == 0:
                return error_message('There was an error while trying to insert the publisher'), 500
            else:
                return jsonify({'publisher_id': publisher_id}), 201            