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
 * limitations under the License
 */

export const _fetch = async (path, payload = "") => {
  const headers = {
    "X-Requested-With": "XMLHttpRequest",
  };
  if (payload && !(payload instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: headers,
    body: payload,
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    if(result.unknownCredId && result.rpID && PublicKeyCredential && PublicKeyCredential.signalUnknownCredential){
      await PublicKeyCredential.signalUnknownCredential({
        rpId:result.rpID,
        credentialId:result.unknownCredId,
      })
    }
    
    throw result.error;
  }
};

export const registerCredential = async (isConditional=false) => {
  const opts = {};
  const options = await _fetch("/auth/registerRequest", opts);

  options.user.id = base64url.decode(options.user.id);
  options.challenge = base64url.decode(options.challenge);

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }

  const cred = await navigator.credentials.create({
    publicKey: options,
    mediation: isConditional? "conditional" : null
  });

  const credential = {};
  credential.id = cred.id;
  credential.rawId = base64url.encode(cred.rawId);
  credential.type = cred.type;

  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject,
    };
  }

  let getparam = ""
  if(isConditional){getparam = "?conditional=1"}
  return await _fetch("/auth/registerResponse"+getparam, credential);
};

export const authenticate = async (username) => {
  const opts = {
    extensions: {},
  };

  let url = "/auth/signinRequest";
  
  if(username){
    url = url + "?username="+ username;
  }

  const options = await _fetch(url, opts);

  if (options.allowCredentials.length === 0) {
    // console.info("No registered credentials found.");
    // return Promise.resolve(null);
  }

  options.challenge = base64url.decode(options.challenge);

  for (let cred of options.allowCredentials) {
    cred.id = base64url.decode(cred.id);
  }

  const cred = await navigator.credentials.get({
    publicKey: options,
  });


  const credential = {};
  credential.id = cred.id;
  credential.type = cred.type;
  credential.rawId = base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };
  }

  return await _fetch(`/auth/signinResponse`, credential);
};

export const unregisterCredential = async (credId) => {
  await _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};

export const deleteUser = async (username) => {
  const ops = {
    username:username
  }
  return await _fetch(`/auth/deleteuser`,ops);
};

export const createUser = async (username,password) => {
  const rand = new Uint8Array(32);
  self.crypto.getRandomValues(rand);
  console.log(rand)
  const salt = base64url.encode(rand)
  console.log(salt)
  
  var hashedPassword
  if(password){
    hashedPassword = await hashPassword(password,salt);
  }
  
  const ops = {
    username:username,
    password:hashedPassword,
    salt:salt
  }
  console.log(JSON.stringify(ops))
  return await _fetch(`/auth/createuser`,ops);
};



export const passwordAuth = async (username,password) => {
  const ops = {
    username:username
  }
  const res = await _fetch(`/auth/getsalt`,ops)

  const salt = res.salt
  const hashedPassword = await hashPassword(password,salt);
  
  const ops2 = {
    username:username,
    password:hashedPassword,
  }
  console.log(JSON.stringify(ops2))
  return await _fetch(`/auth/password`,ops2);
};


// This function hashes password before sending to the server so that the server won't handle raw passwords.
export const hashPassword = async (password, salt) => {
  if(!password){throw "enter password"}
  if(!salt){throw "empty salt"}
  
  const uint8password  = new Uint8Array(new TextEncoder().encode(password));
  const uint8salt = new Uint8Array(base64url.decode(salt));
  const input = new Uint8Array(uint8password.byteLength + uint8salt.byteLength);
  input.set(uint8password);
  input.set(uint8salt,uint8password.byteLength);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return base64url.encode(digest);
};

export const authenticateWithConditionalUi = async (abortSignal) => {
  
  // Availability of `window.PublicKeyCredential` means WebAuthn is usable.  
  if (window.PublicKeyCredential &&  
      PublicKeyCredential.isConditionalMediationAvailable) {  
    // Check if conditional mediation is available.  
    const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();  
    if (!isCMA) {  
      console.error("isConditionalMediationAvailable is false or null");
      return;  
    }  
  }else{
    console.error("window.PublicKeyCredential is false or null");
    return;
  }
  
  const opts = {
    extensions: {},
  };

  let url = "/auth/signinRequest";

  const options = await _fetch(url, opts);

  options.challenge = base64url.decode(options.challenge);


  const cred = await navigator.credentials.get({
    mediation: "conditional",
    publicKey: options,
    signal:abortSignal
  });

  const credential = {};
  credential.id = cred.id;
  credential.type = cred.type;
  credential.rawId = base64url.encode(cred.rawId);


  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };
  }

  return await _fetch(`/auth/signinResponse`, credential);

};

