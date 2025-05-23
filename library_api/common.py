import os
import requests
from flask import current_app
from library_api.database import get_db
from library_api.utils import error_message, convert_to_html_entities

"""
Returns a dictionary with basic book info by ID
"""
def basic_book_info(book_id: int):
    db = get_db()
    book = db.execute(
        '''
        SELECT tbook.cTitle AS title, trim(tauthor.cName || ' ' || tauthor.cSurname) AS author,
            tpublishingcompany.cName AS publishing_company, tbook.nPublishingYear AS publishing_year
        FROM tbook
            INNER JOIN tauthor
                ON tbook.nAuthorID = tauthor.nAuthorID
            INNER JOIN tpublishingcompany
                ON tbook.nPublishingCompanyID = tpublishingcompany.nPublishingCompanyID
        WHERE tbook.nBookID = ?
        ''',
        (book_id,)
    ).fetchone()

    if book == None:
        return error_message('Book not found')
    else:
        cover = ''

        # The book cover is obtained from the book cover API
        try:
            book_cover_base_url = os.getenv('BOOK_COVER_BASE_URL')
            book_title = convert_to_html_entities(book['title'])
            author_name = convert_to_html_entities(book['author'])
            book_cover_url = f'{book_cover_base_url}?book_title={book_title}&author_name={author_name}'

            response = requests.get(book_cover_url, timeout=5)
            response.raise_for_status()

            result = response.json()
            if 'url' in result:
                cover = result['url']

        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Failed to fetch book cover: {e}")

        # The sqlite row is converted to a dictionary
        book_info = {key: book[key] for key in book.keys()}
        book_info['cover'] = cover
        return book_info
    
"""
Validates whether an authentication token exists
"""
def user_by_token(token):
    if not token:
        return 0
    
    db = get_db()
    user = db.execute(
        '''
        SELECT nMemberID AS user_id
        FROM tmember
        WHERE cAuthToken = ?
        ''',
        (token,)
    ).fetchone()

    if user == None:
        return 0
    
    return user['user_id']

"""
Validates whether a user ID and its authentication token match.
If is_admin is true, the user must also be an admin
"""
def token_is_valid(user_id, auth_token, is_admin = False):
    sql = '''
        SELECT COUNT(*) AS total
        FROM tmember
        WHERE nMemberID = ?
        AND cAuthToken = ?
    '''
    if is_admin:
        sql += ' AND bAdmin = 1'

    db = get_db()
    user = db.execute(
        sql, 
        (user_id, auth_token)
    ).fetchone()
    return user['total'] > 0