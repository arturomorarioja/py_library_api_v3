import { expect, test } from '@playwright/test';

const baseRunId = `${Date.now()}-${process.pid}`;
const slug = (value: string) => value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'default';

const makeEnv = (projectName = 'default') => {
  const runId = `${baseRunId}-${slug(projectName)}`;

  return {
    BOOK_ID: process.env.BOOK_ID ?? '1251',
    USER_ID: process.env.USER_ID ?? '13',
    EMAIL_EXISTING_USER: process.env.EMAIL_EXISTING_USER ?? 'laura.m.lind@mail.com',
    PASSWORD_EXISTING_USER: process.env.PASSWORD_EXISTING_USER ?? 'pepe',
    ADDRESS_NEW_USER: process.env.ADDRESS_NEW_USER ?? 'Lygten 37, 2400 København NV',
    EMAIL_NEW_USER: process.env.EMAIL_NEW_USER ?? `jonas.a.krogh.${runId}@mail.com`,
    PASSWORD_NEW_USER: process.env.PASSWORD_NEW_USER ?? 'LibraryAPI24!',
    ADDRESS_EXISTING_USER: process.env.ADDRESS_EXISTING_USER ?? 'Ulriksholmvej 80, 2990 Nivå',
    EMAIL_NEW_USER_UPDATED: process.env.EMAIL_NEW_USER_UPDATED ?? `jonas.a.krogh.new.${runId}@mail.com`,
    ADDRESS_NEW_USER_UPDATED: process.env.ADDRESS_NEW_USER_UPDATED ?? 'Albanigade 66, 1727 København SV',
    NEW_BOOK_TITLE: process.env.NEW_BOOK_TITLE ?? `The Testaments ${runId}`,
    AUTHOR_FIRST_NAME: process.env.AUTHOR_FIRST_NAME ?? 'Karen',
    AUTHOR_LAST_NAME: process.env.AUTHOR_LAST_NAME ?? `Blixen ${runId}`,
    PUBLISHER_NAME: process.env.PUBLISHER_NAME ?? `Nørrebro Publishing ${runId}`,
    EMAIL_ADMIN: process.env.EMAIL_ADMIN ?? 'admin.library@mail.com',
    PASSWORD_ADMIN: process.env.PASSWORD_ADMIN ?? 'WebUdvikling25!',
  };
};

let env = makeEnv();

let newUserId = '';
let authToken = '';
let adminId = '';
let newBookId = '';

const tokenHeader = (token: string) => ({
  'X-Session-Token': token,
});

const newUserMultipart = (overrides: Record<string, string> = {}) => ({
  email: env.EMAIL_NEW_USER,
  password: env.PASSWORD_NEW_USER,
  first_name: 'Jonas A.',
  last_name: 'Krogh',
  address: env.ADDRESS_NEW_USER,
  phone_number: '55555555',
  birth_date: '2001-11-05',
  ...overrides,
});

test.describe.serial('Library API v3 Postman collection', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'API collection should run once, not once per browser project.');

  test.beforeAll(({}, testInfo) => {
    env = makeEnv(testInfo.project.name);
  });

  test('books', async ({ request }) => {
    const response = await request.get(`/books/${env.BOOK_ID}`);

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
  });

  test('books random', async ({ request }) => {
    const response = await request.get('/books?n=15');

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
  });

  test('books search', async ({ request }) => {
    const response = await request.get('/books?s=winter');

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
  });

  test('books by author', async ({ request }) => {
    const response = await request.get('/books?a=32');

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
  });

  test('books ID', async ({ request }) => {
    const response = await request.get(`/books/${env.BOOK_ID}`);
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
    expect(body.title).toBe('Do Androids Dream of Electric Sheep?');
  });

  test('authors', async ({ request }) => {
    const response = await request.get('/authors');

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('author_name');
  });

  test('publishers', async ({ request }) => {
    const response = await request.get('/publishers');

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publisher_name');
  });

  test('users bad params', async ({ request }) => {
    const response = await request.post('/users', { multipart: {} });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('Incorrect parameters');
  });

  test('users existing email', async ({ request }) => {
    const response = await request.post('/users', {
      multipart: newUserMultipart({
        email: env.EMAIL_EXISTING_USER,
        password: 'LibraryAPI24!',
        address: 'Lygten 37, 2400 København NV',
      }),
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('The user already exists');
  });

  test('users bad pwd format', async ({ request }) => {
    const response = await request.post('/users', {
      multipart: newUserMultipart({ password: 'LibraryAPI' }),
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('Incorrect password format');
  });

  test('users', async ({ request }) => {
    const response = await request.post('/users', {
      multipart: newUserMultipart(),
    });
    const body = await response.json();

    expect(response.status()).toBe(201);
    expect(body.user_id).toEqual(expect.any(Number));
    newUserId = String(body.user_id);
  });

  test('auth/login bad nonexisting email', async ({ request }) => {
    const response = await request.post('/auth/login', {
      multipart: {
        email: 'fake@mail.com',
        password: env.PASSWORD_NEW_USER,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Wrong credentials');
  });

  test('auth/login bad pwd', async ({ request }) => {
    const response = await request.post('/auth/login', {
      multipart: {
        email: env.EMAIL_NEW_USER,
        password: 'wrong_password',
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Wrong credentials');
  });

  test('auth/login', async ({ request }) => {
    const response = await request.post('/auth/login', {
      multipart: {
        email: env.EMAIL_NEW_USER,
        password: env.PASSWORD_NEW_USER,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.user_id).toEqual(expect.any(Number));
    authToken = body.auth_token;
    expect(authToken).toEqual(expect.any(String));
  });

  test('users new', async ({ request }) => {
    const response = await request.get(`/users/${newUserId}`, {
      headers: tokenHeader(authToken),
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.address).toBe(env.ADDRESS_NEW_USER);
  });

  test('users/books loan no token', async ({ request }) => {
    await request.post(`/users/${env.USER_ID}/books/${env.BOOK_ID}`);
  });

  test('users/books loan bad token', async ({ request }) => {
    await request.post(`/users/${env.USER_ID}/books/${env.BOOK_ID}`, {
      headers: tokenHeader('faketoken'),
    });
  });

  test('users/books loan', async ({ request }) => {
    await request.post(`/users/${newUserId}/books/${env.BOOK_ID}`, {
      headers: tokenHeader(authToken),
    });
  });

  test('users/books loan again', async ({ request }) => {
    await request.post(`/users/${env.USER_ID}/books/${env.BOOK_ID}`, {
      headers: tokenHeader(authToken),
    });
  });

  test('users bad params update', async ({ request }) => {
    const response = await request.put(`/users/${newUserId}`, {
      headers: tokenHeader(authToken),
      multipart: {},
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('Incorrect parameters');
  });

  test('users no token update', async ({ request }) => {
    const response = await request.put(`/users/${newUserId}`, {
      multipart: {
        email: env.EMAIL_NEW_USER_UPDATED,
        address: env.ADDRESS_NEW_USER_UPDATED,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Missing authentication token');
  });

  test('users bad token update', async ({ request }) => {
    const response = await request.put(`/users/${newUserId}`, {
      headers: tokenHeader('faketoken'),
      multipart: {
        email: env.EMAIL_NEW_USER_UPDATED,
        address: env.ADDRESS_NEW_USER_UPDATED,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Invalid authentication token');
  });

  test('users update', async ({ request }) => {
    const response = await request.put(`/users/${newUserId}`, {
      headers: tokenHeader(authToken),
      multipart: {
        email: env.EMAIL_NEW_USER_UPDATED,
        address: env.ADDRESS_NEW_USER_UPDATED,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.status).toBe('ok');
  });

  test('users new updated', async ({ request }) => {
    const response = await request.get(`/users/${newUserId}`, {
      headers: tokenHeader(authToken),
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.email).toBe(env.EMAIL_NEW_USER_UPDATED);
    expect(body.address).toBe(env.ADDRESS_NEW_USER_UPDATED);
  });

  test('auth/logout', async ({ request }) => {
    await request.delete('/auth/logout', {
      headers: tokenHeader(authToken),
    });
  });

  test('auth/login updated user', async ({ request }) => {
    const response = await request.post('/auth/login', {
      multipart: {
        email: env.EMAIL_NEW_USER_UPDATED,
        password: env.PASSWORD_NEW_USER,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.user_id).toEqual(expect.any(Number));
    authToken = body.auth_token;
    expect(authToken).toEqual(expect.any(String));
  });

  test('users no token delete', async ({ request }) => {
    const response = await request.delete(`/users/${newUserId}`);
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Missing authentication token');
  });

  test('users bad token delete', async ({ request }) => {
    const response = await request.delete(`/users/${newUserId}`, {
      headers: tokenHeader('faketoken'),
    });
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Invalid authentication token');
  });

  test('users delete', async ({ request }) => {
    const response = await request.delete(`/users/${newUserId}`, {
      headers: tokenHeader(authToken),
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.status).toBe('ok');
  });

  test('auth/login admin', async ({ request }) => {
    const response = await request.post('/auth/login', {
      multipart: {
        email: env.EMAIL_ADMIN,
        password: env.PASSWORD_ADMIN,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(200);
    expect(body.user_id).toEqual(expect.any(Number));
    adminId = String(body.user_id);
    authToken = body.auth_token;
    expect(authToken).toEqual(expect.any(String));
  });

  test('admin/books no token', async ({ request }) => {
    const response = await request.get(`/admin/${adminId}/books/${env.BOOK_ID}`);
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Missing authentication token');
  });

  test('admin/books bad token', async ({ request }) => {
    const response = await request.get(`/admin/${adminId}/books/${env.BOOK_ID}`, {
      headers: tokenHeader('faketoken'),
    });
    const body = await response.json();

    expect(response.status()).toBe(401);
    expect(body.error).toBe('Invalid authentication token');
  });

  test('admin/books', async ({ request }) => {
    const response = await request.get(`/admin/${adminId}/books/${env.BOOK_ID}`, {
      headers: tokenHeader(authToken),
    });

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
  });

  test('admin/publishers', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/publishers`, {
      headers: tokenHeader(authToken),
      multipart: {
        name: env.PUBLISHER_NAME,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(201);
    expect(body.publisher_id).toEqual(expect.any(Number));
  });

  test('admin/publishers bad exists', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/publishers`, {
      headers: tokenHeader(authToken),
      multipart: {
        name: env.PUBLISHER_NAME,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('The publisher already exists');
  });

  test('admin/authors', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/authors`, {
      headers: tokenHeader(authToken),
      multipart: {
        first_name: env.AUTHOR_FIRST_NAME,
        last_name: env.AUTHOR_LAST_NAME,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(201);
    expect(body.author_id).toEqual(expect.any(Number));
  });

  test('admin/authors bad exists', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/authors`, {
      headers: tokenHeader(authToken),
      multipart: {
        first_name: env.AUTHOR_FIRST_NAME,
        last_name: env.AUTHOR_LAST_NAME,
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('The author already exists');
  });

  test('admin/books bad params', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/books`, {
      headers: tokenHeader(authToken),
      multipart: {
        author_id: '32',
        publishing_year: '2016',
        publisher_id: '149',
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('Incorrect parameters');
  });

  test('admin/books bad nonexisting author', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/books`, {
      headers: tokenHeader(authToken),
      multipart: {
        title: env.NEW_BOOK_TITLE,
        author_id: '9999',
        publishing_year: '2016',
        publisher_id: '149',
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(404);
    expect(body.error).toBe('The author does not exist');
  });

  test('admin/books bad nonexisting publisher', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/books`, {
      headers: tokenHeader(authToken),
      multipart: {
        title: env.NEW_BOOK_TITLE,
        author_id: '32',
        publishing_year: '2016',
        publisher_id: '9999',
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(404);
    expect(body.error).toBe('The publishing company does not exist');
  });

  test('admin/books create', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/books`, {
      headers: tokenHeader(authToken),
      multipart: {
        title: env.NEW_BOOK_TITLE,
        author_id: '32',
        publishing_year: '2016',
        publisher_id: '149',
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(201);
    expect(body.book_id).toEqual(expect.any(Number));
    newBookId = String(body.book_id);
    expect(newBookId).not.toBe('');
  });

  test('admin/books bad exists', async ({ request }) => {
    const response = await request.post(`/admin/${adminId}/books`, {
      headers: tokenHeader(authToken),
      multipart: {
        title: env.NEW_BOOK_TITLE,
        author_id: '32',
        publishing_year: '2016',
        publisher_id: '149',
      },
    });
    const body = await response.json();

    expect(response.status()).toBe(400);
    expect(body.error).toBe('The book already exists');
  });

  test('auth/logout admin', async ({ request }) => {
    await request.delete('/auth/logout', {
      headers: tokenHeader(authToken),
    });
  });

  test('books final', async ({ request }) => {
    const response = await request.get(`/books/${env.BOOK_ID}`);

    expect(response.status()).toBe(200);
    expect(await response.text()).toContain('publishing_company');
  });
});
