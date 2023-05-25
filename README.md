# nodejs server set up example. You have to install Node js.

For this example use this link to setup a MongoDB connection with free access:
https://www.youtube.com/watch?v=-PdjUx9JZ2E&list=PL0Zuz27SZ-6PFkIxaJ6Xx_X46avTM1aYw&index=13

To start programm:
1. Clone repo
2. Open terminal in main folder
3. Type in cli: npm install
4. Wait till finished
5. You can use PM2 or Nodemon for monitoring and auto restart server
6. Nodemon in dev mode: npm run dev
7. PM2 in dev mode: pm2 start server --watch
Note!!! : 
7. create .env file in your project
9. Type into .env file: ACCESS_TOKEN_SECRET=
10. Open terminal type: node (and hit enter)
11. In the same terminal then type: require("crypto").randomBytes(64).toString("hex");
12. Hit enter
13. Copy all between quotes(not quotes included!)
14. Paste in to .env file after ACCESS_TOKEN_SECRET=
15. In terminal type again: require("crypto").randomBytes(64).toString("hex");
16. Press enter
17. Copy all between quotes(not quotes included!)
18. Paste in to .env file after REFRESH_TOKEN_SECRET=
19. Save file.

Nodemon docs: https://github.com/remy/nodemon#nodemon
PM2 docs: https://pm2.keymetrics.io/docs/usage/quick-start/

useful link: https://nodejs.org/api/http.html#httpmethods



🌱 MongoDB and Mongoose References: 
MongoDB: https://www.mongodb.com/
Mongoose: https://mongoosejs.com/


📚 JWT References:
Intro to JSON Web Tokens: https://jwt.io/introduction
All You Need to Know About Storing JWT in the Frontend: https://dev.to/cotter/localstorage-vs...
NPM jsonwebtoken package: https://www.npmjs.com/package/jsonweb...
NPM cookie-parser package: https://www.npmjs.com/package/cookie-...
Deleting Cookies: http://expressjs.com/en/api.html#res....
Cross-Site Scripting (XSS): https://owasp.org/www-community/attac...
Cross-Site Request Forgery (CSRF): https://owasp.org/www-community/attac...
REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/ch...
JWT: https://datatracker.ietf.org/doc/html/rfc7519

📚 Login References:
Bcrypt: https://www.npmjs.com/package/bcrypt
How to Safely Store a Password: https://codahale.com/how-to-safely-st...
MDN: HTTP Response Status Codes: https://developer.mozilla.org/en-US/d...

📚 More References:
Node.js Official site: https://nodejs.org
NPM Official site: https://www.npmjs.com/
Express JS Official site: https://expressjs.com/
MDN CORS: https://developer.mozilla.org/en-US/d...
NPM CORS: https://www.npmjs.com/package/cors
IANA: https://www.iana.org/assignments/jwt/jwt.xhtml

