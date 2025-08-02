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

// the following two functions are from https://github.com/MasterKale/webauthn-polyfills/blob/main/src/base64url.ts
export const base64url_encode = function(buffer) {
  const base64 = globalThis.btoa(String.fromCharCode(...new Uint8Array(buffer)));
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export const base64url_decode = function(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binStr = globalThis.atob(base64);
  const bin = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
      bin[i] = binStr.charCodeAt(i);
  }
  return bin.buffer;
}

export const registerCredential = async (isConditional=false) => {
  const opts = {};
  const options = await _fetch("/auth/registerRequest", opts);

  const publicKeyCredentialCreationOptions = PublicKeyCredential.parseCreationOptionsFromJSON(options);

  const cred = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions,
    mediation: isConditional? "conditional" : null
  });

  const credential = cred.toJSON();

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

  const publicKeyRequestOptions = PublicKeyCredential.parseRequestOptionsFromJSON(options);

  const cred = await navigator.credentials.get({
    publicKey: publicKeyRequestOptions,
  });

  const credential = cred.toJSON();

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
  const salt = base64url_encode(rand)
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
  const uint8salt = new Uint8Array(base64url_decode(salt));
  const input = new Uint8Array(uint8password.byteLength + uint8salt.byteLength);
  input.set(uint8password);
  input.set(uint8salt,uint8password.byteLength);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return base64url_encode(digest);
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

  const publicKeyRequestOptions = PublicKeyCredential.parseRequestOptionsFromJSON(options);

  const cred = await navigator.credentials.get({
    mediation: "conditional",
    publicKey: publicKeyRequestOptions,
    signal:abortSignal
  });

  const credential = cred.toJSON();

  return await _fetch(`/auth/signinResponse`, credential);
};


export const reAuthenticateWithConditionalUi = async (username) => {
  const opts = {
    extensions: {},
  };

  let url = "/auth/signinRequest";
  
  if(username){
    url = url + "/?username="+ username;
  }

  const options = await _fetch(url, opts);

  const publicKeyRequestOptions = PublicKeyCredential.parseRequestOptionsFromJSON(options);

  const cred = await navigator.credentials.get({
    mediation: "conditional",
    publicKey: publicKeyRequestOptions,
  });

  const credential = cred.toJSON();

  return await _fetch(`/auth/signinResponse`, credential);
};
