# Library API v3
Python Flask API that serves e-book information in the context of a digital online library.

## Endpoints
POST parameters are sent as form-data.

All endpoints marked as "Auth" require authentication via the session token `X-Session-Token`, which will be included in the request's header.

<b>User endpoints</b>:
|Method|Endpoint|POST params|Auth|Description|
|------|--------|-----------|----|-----------|
|GET|/books?n=<number_of_books>|||Retrieve a random number of books|
|GET|/books?s=<search_text>|||Retrieve the books whose title includes a search term|
|GET|/books?a=<author_id>|||Retrieve the books written by a specific author|
|GET|/books/<book_id>|||Retrieve information about a book|
|GET|/authors|||Retrieve all authors|
|GET|/publishers|||Retrieve all publishers|
|GET|/users/<user_id>||X|Retrieve information about a user|
|POST|/users|email, password, first_name, last_name, address, phone_number, birth_date||Create a new user. All parameters are mandatory. Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character|
|PUT|/users/<user_id>||X|email (optional), first_name (optional), last_name (optional), address (optional), phone_number (optional), birth_date (optional)|Update information about a user. At least one parameter must have a value|
|DELETE|/users/<user_id>||X|Delete a user and their loans|
|POST|/users/<user_id>/books/<book_id>||X|Loan a book if it has not been loaned by the same user in the previous 30 days|

<b>Admin endpoints</b>:
|Method|Endpoint|POST params|Auth|Description|
|------|--------|-----------|----|-----------|
|GET|/admin/<user_id>/books/<book_id>||X|Retrieve information about a book and its loan history|
|POST|/admin/<user_id>/books|title, author_id, publisher_id, publishing_year|X|Create a new book. All parameters are mandatory. Year must be lower or equal than the present year|
|POST|/admin/<user_id>/authors|first_name, last_name|X|Create a new author. All parameters are mandatory|
|POST|/admin/<user_id>/publishers|name|X|Create a new publisher. The parameter is mandatory|

<b>Authentication endpoints</b>:
|Method|Endpoint|POST params|Auth|Description|
|------|--------|-----------|----|-----------|
|POST|/auth/login|email, password||Login|
|POST|/auth/logout||X|Logout|

<b>Return values</b>:

- GET /books?n=15
```json
[
    {
        "book_id": 1005,
        "title": "Harry Potter and the Goblet of Fire",
        "publishing_year": 1943,
        "author": "J. K. Rowling",
        "publishing_company": "Labadie-Zboncak"
    },
    {
        "book_id": 1506,
        "title": "The Complete Tales and Poems of Edgar Allan Poe",
        "publishing_year": 1982,
        "author": "Edgar Allan Poe",
        "publishing_company": "Fisher LLC"
    },
    ...
]
```
- GET /books?s=winter
```json
[
    {
        "book_id": 1458,
        "title": "If on a Winter's Night a Traveler",
        "publishing_year": 1967,
        "author": "Italo Calvino",
        "publishing_company": "Treutel, Schuster and Brekke"
    },
    {
        "book_id": 1898,
        "title": "The Long Winter",
        "publishing_year": 1959,
        "author": "Laura Ingalls Wilder",
        "publishing_company": "Stoltenberg and Sons"
    },
    ...
]
```
- GET /books?a=32
```json
[
    {
        "book_id": 1499,
        "title": "Alias Grace",
        "publishing_year": 1972,
        "author": "Margaret Atwood",
        "publishing_company": "Gislason-Parker"
    },
    {
        "book_id": 1701,
        "title": "Cat's Eye",
        "publishing_year": 1974,
        "author": "Margaret Atwood",
        "publishing_company": "Tromp, Johnson and Barrows"
    },
    ...
]
```
- GET /books/1251
```json
{
    "title": "Do Androids Dream of Electric Sheep?",
    "author": "Philip K. Dick",
    "publishing_company": "Frami, Feeney and Hermiston",
    "publishing_year": 2010,
    "cover": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1507838927i/36402034.jpg"
}
```
- GET /authors
```json
[
    {
        "author_id": 1,
        "author_name": "Aeschylus"
    },
    {
        "author_id": 3,
        "author_name": "Aristotle"
    },
    ...
]
```
- GET /publishers
```json
[
    {
        "publisher_id": 98,
        "publisher_name": "Adams Group"
    },
    {
        "publisher_id": 135,
        "publisher_name": "Armstrong Inc"
    },
    ...
]
```
- GET /users/13
```json
{
    "email": "laura.m.lind@mail.com",
    "first_name": "Laura M.",
    "last_name": "Lind",
    "address": "Ulriksholmvej 80, 2990 Nivå",
    "phone_number": "004550724315",
    "birth_date": "1979-02-01",
    "membership_date": "2013-09-05"
}
```
- POST /users
```json
{
    "user_id": 2683
}
```
```json
{
    "error": "Incorrect parameters"
}
```
```json
{
    "error": "The user already exists"
}
```
```json
{
    "error": "Incorrect password format"
}
```
- DELETE /users/2683
```json
{
    "status": "ok"
}
```
- POST /auth/login
```json
{
    "user_id": 2683,
    "auth_token": "899a3173-d1bf-4a80-ae70-2c8377be2b02",
    "is_admin": 0
}
```
```json
{
    "error": "Wrong credentials"
}
```
- PUT /users/2683
```json
{
    "status": "ok"
}
```
```json
{
    "error": "Incorrect parameters"
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```
- POST /users/13/books/1251
```json
{
    "status": "ok"
}
```
```json
{
    "error": "This user has still this book on loan"
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```
- GET /admin/2687/books/1251
```json
{
    "title": "Do Androids Dream of Electric Sheep?",
    "author": "Philip K. Dick",
    "publishing_company": "Frami, Feeney and Hermiston",
    "publishing_year": 2010,
    "cover": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1507838927i/36402034.jpg",
    "loans": [
        {
            "user_id": 966,
            "loan_date": "2013-12-19"
        },
        {
            "user_id": 1586,
            "loan_date": "2015-04-19"
        },
        ...
    ]
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```
- POST /admin/2687/books
```json
{
    "book_id": 1999
}
```
```json
{
    "error": "Incorrect parameters"
}
```
```json
{
    "error": "The author does not exist"
}
```
```json
{
    "error": "The publishing company does not exist"
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```
- POST /admin/2687/authors
```json
{
    "author_id": 510
}
```
```json
{
    "error": "Incorrect parameters"
}
```
```json
{
    "error": "The author already exists"
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```
- POST /admin/2687/publishers
```json
{
    "publisher_id": 158
}
```
```json
{
    "error": "Incorrect parameters"
}
```
```json
{
    "error": "The publisher already exists"
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```
- POST /auth/logout
```json
{
    "status": "ok"
}
```
```json
{
    "error": "Missing authentication token"
}
```
```json
{
    "error": "Invalid authentication token"
}
```

## Execution
1. Start Docker Desktop
2. In the command line, run `docker-compose up -d`

The API will be available at `http://localhost:8080`.

## Testing
A Postman collection and the corresponding Postman environment are included in the `postman` folder.

## Data reset
In case a data reset is necessary, the original database is at `data/librarylite_original.db`. It can be copied to `data/librarylite.db`. A Docker image rebuild might be necessary for a full database reset.

## Tools
SQLite3 / Flask / Python

## Author
Arturo Mora-Rioja