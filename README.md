# BcryptJS Passport JS Authentication

This is a passport JS **Authentication** example app with hashed passwords thanks to bcryptjs.

_NOTE: This app is meant to only show how to use Passport JS. I would suggest to implement this feature with production ready design patterns such as [MVC](https://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller)._

## Installation

- Add a .env file in the root directory your MongoDB URI:
  `MONGODB_URI='YOUR_MONGODB_URI'`

- Then, RUN:

```bash
npm i
npm start
```

- Open your browser and go to `http://localhost:3000`

  _NOTE: Use a private browser window to test the app as it uses cookies_

## What to do in the app ?

1. visit `/signup` to create a new user
2. login using username and password
3. logout by clicking the logout button

_Visit [bcryptjs](https://www.npmjs.com/package/bcryptjs) and [Passport JS](http://www.passportjs.org) for more information_
Browse other [Passport JS strategies](http://www.passportjs.org/packages/)
