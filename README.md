# About

![ ][logo]

*Occultus*  (meaning “hidden, secret.” in  Latin) is a [libsignal] based
library for building platforms which help you stay connected  with  your
friends, family, and other devices, **securely**. All  the communication
with  Occultus  is  **End-To-End** Encrypted. It was created by *Asheesh
Sharma* as  a  generic  **E2EE**  system for building much  more complex
systems such as secure internet of things, smart homes, and chats.

Internally, Occultus uses [libsignal] by [Open Whisper Systems]  for the
actual  data  encryption. With  Occultus, the  goal  was  to wrap around
[libsignal-node]; from its "messy" inticrate details and provide:

1. an  encrpyted  client-side interface  to  store important information
like chats, and Signal protocol's own handshake related stuff;
2. a secure client-side server interface to handle key sharing;
3. a Whatsapp style message [encryption for groups];
4. an all in typescript solution! ☝😎

For implementation details please refer to the [Occultus] Class.

## Security check status

The  checklist  is  based   on   [this   medium   article].  Note   that
**not required** does not imply that the  security issues  will  not  be
considered  in  the  future.  Most   of  them  deal  with  server   side
communication  which  shall  be  implemented  within [SignalServerStore]
interface or outside in its implimentation class.

![OWASP][XSS]

* [x] Escape HTML, JS and CSS output **not required**

![OWASP][Threats-DDOS]

* [x] Limit concurrent requests using a middleware **not required**
* [x] Prevent evil RegEx from overloading your single  thread  execution
    **not required**
* [x] Re-generate client-side store keys randomly b/w writes.

    The database automatically  generates  a  new  encryption  key  when
    something is written to it. For  performance  and  security reasons,
    this  is  done  randomly  with  a  probability  of 0.5  which is not
    configurable.

* [x] Avoid  DOS  attacks  by  explicitly  setting when a process should
    crash **not required**

![OWASP][A1 Injection]

* [x] Linting rule checks
* [x] Prevent query injection vulnerabilities with ORM/ODM libraries
* [x] Avoid module loading using a variable

    The store database requires a path which is a variable  supposed  to
    be  configured  by  the  user.  According  to   this  vulnerability,
    malicious  user input could  find its  way  to  the  database's path
    variable which can be used to tamper the file. So, although we can't
    take away  this configuaration  flexibility, but  we  can  hide  the
    database as a private during runtime. This is what has been done.

* [x] Take extra care when working with child processes **not required**
* [x] Prevent unsafe redirects **not required**

![OWASP][A4 External Entities]

* [x] Avoid JavaScript eval statements **not required**
* [x] Run unsafe code in a sandbox **not required**

![OWASP][A6 Security Misconfiguration]

* [ ] Avoid publishing secrets to the npm registry **not required**
* [ ] Modify session middleware settings **not required**
* [ ] Configure 2FA for npm or Yarn **not required**
* [ ] Hide error details from clients
* [ ] Adjust the HTTP response headers for enhanced security
* [ ] Extract secrets from config files or use packages to encrypt them

![OWASP][A8 Insecured Deserializaiton]

* [ ] Validate incoming JSON schemas
* [ ] Limit payload size using a reverse-proxy or a middleware

![OWASP][A9 Known Vulnerabilities]

* [x] Constantly and automatically inspect for vulnerable dependencies

    Can  be  done by running `npm audit`  and `npm run snyk` for a [snyk]
    report.

![OWASP][A9 Broken Authentication]

* [x] Avoid using the Node.js crypto library for handling passwords, use
    Bcrypt

    Crypto's Encryption keys, are now hashed with Bcrypt. This  requires
    for the user to provide a password. The database first authenticates
    over  the  provided  password  using  bcrypt  before  it  can  start
    interacting with the [Store] class. This makes it more difficult for
    the  outsider  to  decrypt   the  actual  database   which  for  all
    intended purposes, a JSON string.
    ![clientDb interactions](media/clientDBMS.svg)

    All that is needed however, is  to make sure that  the  database and
    the key is stored somewhere safe.
* [x] Support blacklisting JWT tokens **not required**
* [x] Limit the allowed login requests of each user **not required**

[logo]: media/logo.png
[XSS]: https://img.shields.io/badge/OWASP%20Threats-XSS%20100%25-green.svg
[Threats-DDOS]: https://img.shields.io/badge/OWASP%20Threats-DDOS%20100%25-green.svg
[A1 Injection]: https://img.shields.io/badge/OWASP%20Threats-A1:Injection%20100%25-green.svg
[A4 External Entities]: https://img.shields.io/badge/OWASP%20Threats-A4:External%20Entities%20100%25-green.svg
[A6 Security Misconfiguration]: https://img.shields.io/badge/OWASP%20Threats-A6:Security%20Misconfiguration%200%25-red.svg
[A8 Insecured Deserializaiton]: https://img.shields.io/badge/OWASP%20Threats-A8:Insecured%20Deserializaiton%200%25-red.svg
[A9 Known Vulnerabilities]: https://img.shields.io/badge/OWASP%20Threats-A9:Known%20Vulnerabilities%20100%25-green.svg
[A9 Broken Authentication]: https://img.shields.io/badge/OWASP%20Threats-A9:Broken%20Authentication%20100%25-green.svg
[Occultus]: ./classes/_index_.occultus.html
[Store]: ./modules/_signalclientstore_.html
[SignalServerStore]: modules/_signalserverstore_.html
[libsignal]: https://github.com/signalapp/libsignal-protocol-javascript
[Open Whisper Systems]: https://www.whispersystems.org
[libsignal-node]: https://www.npmjs.com/package/libsignal
[encryption for groups]: https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf
[this medium article]: https://medium.com/@nodepractices/were-under-attack-23-node-js-security-best-practices-e33c146cb87d
[snyk]: https://snyk.io/
