/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 * ======================================================================
 * The following License applies to the modifications or "Derivative Works" 
 * made to the original Works.
 * To see what constitutes the Derivative Works, please refer to the repository's commit log.
 * https://github.com/kkoiwai/passkey-example/
 *
 * Copyright 2024 Kosuke Koiwai All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const fido2 = require("@simplewebauthn/server");
const base64url = require("base64url");
const fs = require("fs");
const low = require("lowdb");

if (!fs.existsSync("./.data")) {
  fs.mkdirSync("./.data");
}

const FileSync = require("lowdb/adapters/FileSync");
const adapter = new FileSync(".data/db.json");
const db = low(adapter);

router.use(express.json());

const RP_NAME = "WebAuthn Codelab";
const TIMEOUT = 30 * 1000 * 60;

db.defaults({
  users: [],
  passkeys: [],
  passwords: [],
}).write();

/**
 * Checks CSRF protection using custom header `X-Requested-With`
 **/
const csrfCheck = (req, res, next) => {
  if (req.header("X-Requested-With") != "XMLHttpRequest") {
    res.status(400).json({ error: "invalid access." });
    return;
  }
  next();
};

/**
 * If the session doesn't contain `signed-in`, consider the user is not authenticated.
 **/
const sessionCheck = (req, res, next) => {
  if (!req.session["signed-in"]) {
    res.status(401).json({ error: "not signed in." });
    return;
  }
  next();
};


/**
 * If the user agent contains okhttp, the client is an android app 
 * with a regacy FIDO2 implementation and apk hash should be used as the origin.
 * Otherwise, the origin should be https://domain.com
 **/
const getOrigin = (userAgent) => {
  let origin = "";
  if (userAgent.indexOf("okhttp") === 0) {
    const octArray = process.env.ANDROID_SHA256HASH.split(":").map((h) =>
      parseInt(h, 16)
    );
    const androidHash = base64url.encode(octArray);
    origin = `android:apk-key-hash:${androidHash}`;
  } else {
    origin = process.env.ORIGIN;
  }
  return origin;
};

/**
 * Set a `username` in the session if the username exists.
 * Note that the user is not yet "authenticated."
 * The session value is used for the log in, such as saving challenge.
 **/
router.post("/username", (req, res) => {
  const username = req.body.username;
  if (!username || !/[a-zA-Z0-9-_]+/.test(username)) {
    res.status(400).send({ error: "Bad request" });
    return;
  } else {
    // See if account already exists
    let user = db.get("users").find({ username: username.toLowerCase() }).value();
    // If user entry is not created yet, return error
    if (!user) {
      res.status(400).send({ error: "Username not found." });
      return;
    }
    // Set username in the session
    req.session.username = username;
    // redirect to `/home`.
    res.json(user);
  }
});

/**
 * Verifies user credential and let the user sign-in.
 * No preceding registration required.
 * This only checks if `username` is not empty string and ignores the password.
 **/
router.post("/password", (req, res) => {
  console.log(
    "password request: " + (req.body ? JSON.stringify(req.body) : "")
  );

  if (!req.body.username) {
    res.status(401).json({ error: "Enter username first." });
    return;
  }

  if (!req.body.password) {
    res.status(401).json({ error: "Enter password." });
    return;
  }
  const user = db.get("users").find({ username: req.body.username.toLowerCase() }).value();

  if (!user) {
    res.status(401).json({ error: "username not found." });
    return;
  }

  const password = db.get("passwords").find({ userId: user.id }).value();

  if (!password) {
    res.status(401).json({ error: "Password not registered." });
    return;
  }

  if (password && password.password == req.body.password) {

    req.session.username = user.username;
    req.session["signed-in"] = "yes";
    res.json(user);
  } else {
    res.status(400).json({ error: "wrong password." });
  }
});

router.get("/signout", (req, res) => {
  // Remove the session
  req.session.destroy();
  // Redirect to `/`
  res.redirect(302, "/");
});


router.post("/signout", (req, res) => {
  // Remove the session
  req.session.destroy();
  res.json({ "signout": "success" });
});

/**
 * Returns a credential id
 * (This server only stores one key per username.)
 * Response format:
 * ```{
 *   username: String,
 *   credentials: [Credential]
 * }```

 Credential
 ```
 {
   credId: String,
   publicKey: String,
   aaguid: ??,
   prevCounter: Int
 };
 ```
 **/
router.post("/getKeys", csrfCheck, sessionCheck, (req, res) => {
  console.log("getKeys request: " + (req.body ? JSON.stringify(req.body) : ""));
  console.log(req.session)

  const user = db.get("users").find({ username: req.session.username }).value();
  const credentials = db.get("passkeys").filter({ passkey_user_id: user.id });

  res.json({ rpID: process.env.HOSTNAME, user_id: user.id, credentials: credentials } || {});
});

/**
 * Removes a credential id attached to the user
 * Responds with an unknownCredential object for the use of Signal API
 **/
router.post("/removeKey", csrfCheck, sessionCheck, (req, res) => {
  console.log(
    "removeKey request: " + (req.body ? JSON.stringify(req.body) : "")
  );

  const credId = req.query.credId;
  const username = req.session.username;
  const user = db.get("users").find({ username: username }).value();

  db.get("passkeys")
    .remove({ passkey_user_id: user.id, credId: credId })
    .write();

  res.json({});
});


/**
 * Respond with required information to call navigator.credential.create()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{  // @herrjemand
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     excludeCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }```
 **/
router.post("/registerRequest", csrfCheck, sessionCheck, async (req, res) => {
  console.log("registerRequest request: " + JSON.stringify(req.body));
  const username = req.session.username;
  const user = db.get("users").find({ username: username }).value();

  const credentials = db.get("passkeys").filter({ passkey_user_id: user.id });
  console.log("credentials" + JSON.stringify(credentials))

  const excludeCredentials = [];
  try {
    // if (credentials.length > 0) {
    for (let cred of credentials) {
      excludeCredentials.push({
        id: cred.credId,
        type: "public-key",
        transports: ["internal"],
      });


      console.log("excludeCredentials" + JSON.stringify(excludeCredentials))
      // }
    }

    console.log("excludeCredentials" + JSON.stringify(excludeCredentials))

    // const pubKeyCredParams = [];
    // // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
    // const params = [-7, -257];
    // for (let param of params) {
    //   pubKeyCredParams.push({ type: "public-key", alg: param });
    // }

    // Generate registration options for WebAuthn create
    const options = fido2.generateAttestationOptions({
      rpName: RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.username,
      timeout: TIMEOUT,
      // Prompt users for additional information about the authenticator.
      attestationType: "none",
      // Prevent users from re-registering existing authenticators
      excludeCredentials,
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        requireResidentKey: true,
        userVerification: "required",
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // Keep the challenge in the session
    req.session.challenge = options.challenge;

    // // Temporary hack until SimpleWebAuthn supports `pubKeyCredParams`
    // options.pubKeyCredParams = [];
    // for (let param of params) {
    //   options.pubKeyCredParams.push({ type: "public-key", alg: param });
    // }

    res.json(options);
  } catch (e) {
    res.status(400).send({ error: e });
  }
});

/**
 * Register user credential.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post("/registerResponse", csrfCheck, sessionCheck, async (req, res) => {
  console.log("registerResponse request: " + JSON.stringify(req.body));

  const username = req.session.username;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get("User-Agent"));
  const expectedRPID = process.env.HOSTNAME;
  const credId = req.body.id;
  const type = req.body.type;

  try {
    const { body } = req;

    const verification = await fido2.verifyAttestationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });
    console.log("registering verification: " + JSON.stringify(verification));

    const { verified, authenticatorInfo } = verification;

    if (!verified) {
      throw "User verification failed.";
    }

    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;

    const user = db.get("users").find({ username: username }).value();
    console.log("registering a passkey for a user: " + JSON.stringify(user));
    const date = new Date();
    const timestamp = date.toISOString();

    const existingCred = db
      .get("passkeys")
      .find({ credId: base64CredentialID })
      .value();
    if (existingCred) {
      throw "credential alreay exists.";
    } else {
      /**
       * Add the returned passkey
       */
      db.get("passkeys")
        .push({
          credId: base64CredentialID,
          passkey_user_id: user.id,
          publicKey: base64PublicKey,
          prevCounter: counter,
          created: timestamp,
        })
        .write();
    }

    delete req.session.challenge;

    // Respond with user info
    res.json(user);
  } catch (e) {
    console.error(e.message);
    console.error(e.stack);
    delete req.session.challenge;
    res.status(400).send({ error: e.message });
  }
});

/**
 * Respond with required information to call navigator.credential.get()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     challenge: String,
     userVerification: ('required'|'preferred'|'discouraged'),
     allowCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...]
 * }```
 **/
router.post("/signinRequest", csrfCheck, async (req, res) => {
  console.log(
    "signinRequest request: " + (req.body ? JSON.stringify(req.body) : "")
  );
  console.log(JSON.stringify(req.session));

  try {
    const username = req.query.username ? req.query.username.toLowerCase() : ""

    const user = db
      .get("users")
      .find({ username: req.session.username || username })
      .value();

    // if username is specified but not found in the db,
    if (req.query.username && !user) {
      throw "specified user not found.";
    }

    const allowCredentials = [];
    // if user id is specified, fill allowCredentials
    if (user) {
      const credentials = db
        .get("passkeys")
        .filter({ passkey_user_id: user.id });
      if (!credentials || !credentials.length) {
        throw "credentials for the user not found.";
      }
      for (let cred of credentials) {
        allowCredentials.push({
          id: cred.credId,
          type: "public-key",
          transports: ["internal"],
        });
      }
    }

    const userVerification = "required";

    const options = fido2.generateAssertionOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      userVerification,
    });
    req.session.challenge = options.challenge;
    console.log("returning signinRequest: " + JSON.stringify(options));

    res.json(options);
  } catch (e) {
    console.error(e.message);
    console.error(e.stack);
    res.status(400).json({ error: e });
  }
});

/**
 * Authenticate the user.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       authenticatorData: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post("/signinResponse", csrfCheck, async (req, res) => {
  console.log("signinResponse request: " + JSON.stringify(req.body));
  console.log(JSON.stringify(req.session));

  const { body } = req;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get("User-Agent"));
  const expectedRPID = process.env.HOSTNAME;

  try {
    // Query the user
    var user = db.get("users").find({ username: req.session.username }).value();
    var credential;
    if (user) {
      console.log("user specified in session");
      credential = db
        .get("passkeys")
        .find({ passkey_user_id: user.id, credId: req.body.id })
        .value();
    } else {
      console.log("user not spesified in session (Conditional UI)");
      credential = db.get("passkeys").find({ credId: req.body.id }).value();

      if (!credential) {
        throw "Authenticating credential not found.";
      }
      user = db.get("users").find({ id: credential.passkey_user_id }).value();
      req.session.username = user.username;
    }

    if (!credential) {
      throw "Authenticating credential not found.";
    }

    const verification = fido2.verifyAssertionResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: credential,
    });

    const { verified, authenticatorInfo } = verification;

    if (!verified) {
      throw "User verification failed.";
    }
    console.log(JSON.stringify(authenticatorInfo));

    credential.prevCounter = authenticatorInfo.counter;

    db.get("passkeys").find({ id: credential.id }).assign(credential).write();

    delete req.session.challenge;
    req.session["signed-in"] = "yes";
    res.json(user);
  } catch (e) {
    console.error(e.message);
    console.error(e.stack);
    delete req.session.challenge;
    res.status(400).json({ error: e, unknownCredId: req.body.id, rpID: process.env.HOSTNAME });
  }
});

router.post("/createuser", (req, res) => {
  console.log(
    "createuser request: " + (req.body ? JSON.stringify(req.body) : "")
  );
  const username = req.body.username.toLowerCase();
  const password = req.body.password;
  const salt = req.body.salt;
  const user = db.get("users").find({ username: username }).value();
  const date = new Date();
  const timestamp = date.toISOString();

  if (user) {
    res.status(400).json({ error: "user already exists" });
  } else {
    const newuser = {
      username: username,
      id: base64url.encode(crypto.randomBytes(32)),
      created: timestamp,
    };
    db.get("users").push(newuser).write();

    if (password) {
      const newpassword = {
        userId: newuser.id,
        password: password,
        salt: salt,
        created: timestamp,
      };
      db.get("passwords").push(newpassword).write();
    }

    req.session.username = username;
    req.session["signed-in"] = "yes";
    res.json(newuser);
  }
});

router.post("/deleteuser", (req, res) => {
  console.log(
    "deleteuser request: " + (req.body ? JSON.stringify(req.body) : "")
  );

  if (!req.body.username) {
    res.status(400).json({ error: "Enter username." });
  }

  const username = req.body.username.toLowerCase();
  const user = db.get("users").find({ username: username }).value();
  console.log(
    "delete user: " + JSON.stringify(user)
  );

  if (user) {
    db.get("passkeys").remove({ passkey_user_id: user.id }).write();

    db.get("passwords").remove({ userId: user.id }).write();

    db.get("users").remove({ username: username }).write();
    res.json({});
  } else {
    res.status(400).json({ error: "user not found" });
  }
});


router.get("/resetDB", (req, res) => {
  db.set("users", []).write();
  db.set("passkeys", []).write();
  db.set("passwords", []).write();
  const users = db.get("users").value();
  res.json(users);
});


router.post("/getsalt", (req, res) => {
  console.log("getsalt request: " + (req.body ? JSON.stringify(req.body) : ""));

  const username = req.body.username.toLowerCase();
  const user = db.get("users").find({ username: username }).value();
  if (!user) {
    // if user is not found, then new user is being created, so return new salt
    res.json({ salt: base64url.encode(crypto.randomBytes(32)) });
  } else {
    // if user is found, find salt in db and return.
    const password = db.get("passwords").find({ userId: user.id }).value();
    if (password) {
      res.json({ salt: password.salt });
    } else {
      res.json({ salt: base64url.encode(crypto.randomBytes(32)) });
    }
  }
});

module.exports = router;
