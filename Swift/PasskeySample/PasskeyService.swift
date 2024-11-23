//
//  PasskeyService.swift
//  PasskeySample
//
//  Created by Kosuke Koiwai on 2024/06/02.
//

import Foundation
import AuthenticationServices
import CryptoKit


struct Passkey: Identifiable {
    var id = UUID()
    let created:String
    let credId:String
    let passkey_user_id: String
    let publicKey:String
}

extension String: LocalizedError {
    public var errorDescription: String? { return self }
}

class PasskeyService: NSObject, ObservableObject, ASAuthorizationControllerPresentationContextProviding, ASAuthorizationControllerDelegate {
    @Published var isLoggedIn: Bool = false
    @Published var errorMessage: String?
    @Published var processType: String = ""
    @Published var sessionUserName: String = ""
    
    // TODO: domain を自身のものに変更してください。associated domains設定も忘れないこと。
    let domain = "passkey-example.glitch.me"

    var authenticationAnchor: ASPresentationAnchor?
    
    // make ASAuthorizationController a class-scoped variable so that can be cancelled
    private var authController:ASAuthorizationController?

    func authenticateWithPasskey(autofill:Bool=false) {
        print("authenticateWithPasskey called")
        self.processType = "Authentication"
        Task{
            let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)

            let challenge = await getChallengeForAuthenticationFromServer()
            let assertionRequest = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: challenge)
            
            // cancel previous authController session if exists
            authController?.cancel()
            authController = nil
            
            if(autofill){ 
                authController = ASAuthorizationController(authorizationRequests: [ assertionRequest ] )
                authController!.delegate = self
                authController!.presentationContextProvider = self
                authController!.performAutoFillAssistedRequests()
            }else{
                authController = ASAuthorizationController(authorizationRequests: [ assertionRequest ] )
                authController!.delegate = self
                authController!.presentationContextProvider = self
                authController!.performRequests()
            }
        }
    }
    
    
    func authenticateWithPassword(username:String, password:String) {
        self.processType = "Authentication"
        Task{
            do{
                let jsonObjectForSalt: [String: Any] = [
                    "username": username
                ]
                let postbodyForSalt  = try JSONSerialization.data(withJSONObject: jsonObjectForSalt)
                let objectForSalt = try await fetch(path:"/auth/getsalt", postbody: postbodyForSalt)
                print(objectForSalt)
                guard let salt = objectForSalt["salt"] as? String else{throw "User not found."}
                let hashedPassword = hashPassword(password: password, salt: salt)
                let jsonObjectForAuth: [String: Any] = [
                    "username": username,
                    "password":hashedPassword
                ]
                let postbodyForAuth  = try JSONSerialization.data(withJSONObject: jsonObjectForAuth)
                let object = try await fetch(path:"/auth/password", postbody: postbodyForAuth)
                guard let sessionUsername = object["username"] as? String else{throw "User not found."}
                print(sessionUsername)
                self.sessionUserName = sessionUsername
                await MainActor.run {
                    self.sessionUserName = sessionUsername
                    self.isLoggedIn = true
                }
            } catch let error {
                await MainActor.run {
                    self.errorMessage="Error signing in with password.\n"+error.localizedDescription
                }
            }
        }
    }

    func register(username:String, password:String) {
        self.processType = "Registration"
        Task{
            do{
                var hashedPassword:String = ""
                var salt:String = ""
                if(password != ""){
                    let rand = getRandomBytes(size:32)
                    salt = base64url(data:rand)
                    hashedPassword = hashPassword(password:password, salt:salt)
                }
                let jsonObject: [String: Any] = [
                    "username": username,
                    "password": hashedPassword,
                    "salt": salt
                ]
                print("jsonObject created: \(jsonObject)")
                let postbody  = try JSONSerialization.data(withJSONObject: jsonObject)
                let object = try await fetch(path:"/auth/createuser", postbody: postbody)
                print(object)
                
                // TODO: handle error when user already exists
                guard let sessionUsername = object["username"] as? String else{
                    let errormsg = object["error"] as? String ?? "Error creating user"
                    throw errormsg
                }
                print(sessionUsername)
                await MainActor.run {
                    self.sessionUserName = sessionUsername
                    self.isLoggedIn = true
                }
                
                // create passkey
                guard let (challenge, userName, userID) = await getChallengeForRegistrationFromServer()  else { return  }
                let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
                let registrationRequest = publicKeyCredentialProvider.createCredentialRegistrationRequest(
                    challenge: challenge,
                    name: userName,
                    userID: userID
                )
                
                // cancel previous authController session if exists
                authController?.cancel()
                authController = nil
                authController = ASAuthorizationController(authorizationRequests: [ registrationRequest ] )
                authController!.delegate = self
                authController!.presentationContextProvider = self
                authController!.performRequests()
                
            } catch let error {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
    
    func signout() {
        Task{
            do{
                let postbody  = try JSONSerialization.data(withJSONObject: [])
                let _ = try await fetch(path:"/auth/signout", postbody: postbody)
            } catch let error {
                await MainActor.run {
                    self.isLoggedIn = false
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
    
    
    internal func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        guard let window = UIApplication.shared.windows.first(where: \.isKeyWindow) else { fatalError("The view was not in the app's view hierarchy!") }
        return window
    }
    
    
    func initialSignInWithPasskey(anchor: ASPresentationAnchor, preferImmediatelyAvailableCredentials: Bool) {
        print("signInWith")
        self.authenticationAnchor = anchor
        let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)

        Task{
            // Fetch the challenge from the server.
            let challenge = await getChallengeForAuthenticationFromServer()
            
            let assertionRequest = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: challenge)
            
            // Also allow the user to use a saved password.
            let passwordCredentialProvider = ASAuthorizationPasswordProvider()
            let passwordRequest = passwordCredentialProvider.createRequest()
            
            // cancel previous authController session if exists
//            authController?.cancel()
//            authController = nil
            
            // Pass in any mix of supported sign-in request types.
            let authController = ASAuthorizationController(authorizationRequests: [ assertionRequest, passwordRequest ] )
            authController.delegate = self
            authController.presentationContextProvider = self
            
            if preferImmediatelyAvailableCredentials {
                authController.performRequests(options: .preferImmediatelyAvailableCredentials)
            } else {
                authController.performRequests()
            }
            
//            isPerformingModalReqest = true
        }
    }
   
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        print("authorizationController called")
        switch authorization.credential {
            
            case let credentialRegistration as ASAuthorizationPlatformPublicKeyCredentialRegistration:
                print("authorizationController called with credentialRegistration")
                Task{
                    do{
                        let registrationObject = getRegistrationObject(credentialRegistration: credentialRegistration)
                        let postbody  = try JSONSerialization.data(withJSONObject: registrationObject)
                        let object = try await fetch(path:"/auth/registerResponse", postbody: postbody)

                        print(object)
                        guard let sessionUsername = object["username"] as? String 
                        else{
                            throw object["error"] as? String ?? ""
                        }
                        print(sessionUsername)
//                        await MainActor.run {
//                            self.sessionUserName = sessionUsername
//                            self.isLoggedIn = true
//                        }
                    } catch let error {
                        await MainActor.run {
                            self.errorMessage="Error creating a passkey.\n"+error.localizedDescription
                        }
                    }
                }
                
            case let credentialAssertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
                print("authorizationController called with credentialAssertion")
                Task{
                    do{
                        let assertionObject = getAssersionObject(credentialAssertion: credentialAssertion)
                        let postbody  = try JSONSerialization.data(withJSONObject: assertionObject)
                        let object = try await fetch(path:"/auth/signinResponse", postbody: postbody)

                        print(object)
                        guard let sessionUsername = object["username"] as? String else{throw "User not found."}
                        print(sessionUsername)
                        self.sessionUserName = sessionUsername
                        await MainActor.run {
                            self.sessionUserName = sessionUsername
                            self.isLoggedIn = true
                        }
                    } catch let error {
                        await MainActor.run {
                            self.errorMessage="Error signing in with passkey.\n"+error.localizedDescription
                        }
                    }
                }
                
            case let passwordCredential as ASPasswordCredential:
                print("authorizationController called with passwordCredential")

                let userName = passwordCredential.user
                let password = passwordCredential.password
                
                authenticateWithPassword(username:userName, password:password)
            
            default:
                fatalError("Received unknown authorization type.")
        }
    }
    
    internal func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        guard let authorizationError = error as? ASAuthorizationError else {
            print("Unexpected authorization error: \(error.localizedDescription)")
            Task{
                await MainActor.run  {
                    self.errorMessage="Unknown error. please retry."
                }
            }
            return
        }

        if authorizationError.code == .canceled {
            print("Request cancelled.")
            Task{
                await MainActor.run  {
                    self.errorMessage="Authentication Cancelled"
                }
            }
        } else {
            print("Error: \((error as NSError).userInfo)")
            Task{
                await MainActor.run  {
                    self.errorMessage="Authentication Error"
                }
            }
        }
    }
    
    
    func fetchPasskeys() async -> [Passkey] {
        do{
            let object = try await fetch(path:"/auth/getKeys", postbody: nil)
            if object["credentials"] == nil {}
            print(object)
            // Ensure the NSArray contains dictionaries
            guard let arrayOfDicts = object["credentials"] as? [[String: Any]] else {
                throw "user's passkey not found"
            }
            
            // Map the NSArray to an array of User objects
            let dateFormatter = DateFormatter()
            let passkeys = arrayOfDicts.compactMap { dict -> Passkey? in
                guard let credId = dict["credId"] as? String,
                      let passkey_user_id = dict["publicKey"] as? String,
                      // let created = dateFormatter.date(from: dict["created"] as! String),
                      let created = dict["created"] as? String,
                      let publicKey = dict["publicKey"] as? String else {
                    return nil
                }
                return Passkey(created:created, credId:credId, passkey_user_id:passkey_user_id, publicKey:publicKey)
            }
            return passkeys
        } catch let error {
            print(error.localizedDescription)
            return []
        }
    }
    
    func removeKey(credId:String){
        Task{
            do{
                let object = try await fetch(path:"/auth/removeKey?credId="+credId.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!, postbody: nil)
                print(object)
            }catch let error {
                print(error.localizedDescription)
                return
            }
        }
        
    }
    
    private func getChallengeForAuthenticationFromServer() async -> Data {
        // Fetch the challenge from the server.
        do{
            let object = try await fetch(path:"/auth/signinRequest", postbody: nil)
            if object["challenge"] == nil {throw "user's passkey not found"}
            return base64url(str:object["challenge"] as! String )
        } catch let error {
            print(error.localizedDescription)
            return Data()
        }
    }
    
    private func getChallengeForRegistrationFromServer() async -> (challenge:Data, userName:String, userId:Data)? {
        // Fetch the challenge from the server. The server already has username because the user is created in the ssession
        do{
            let object = try await fetch(path:"/auth/registerRequest", postbody: nil)
            print(object["challenge"] as Any)
            let userIdB64 = base64urlToBase64(base64url: (object["user"]as![String: String])["id"]!)
            let challengeB64 = base64urlToBase64(base64url: object["challenge"] as! String)
            let userName = (object["user"]as![String: String])["name"]!
            print(userName)
            let userId = Data(base64Encoded:userIdB64)!
            let challenge = Data(base64Encoded:challengeB64)!
            return (challenge, userName, userId)
        } catch let error {
            return nil
        }

    }
    
    
    private func getRegistrationObject(credentialRegistration:ASAuthorizationPlatformPublicKeyCredentialRegistration)
    -> [String: Any]{
        let attestationObject = base64url(data:credentialRegistration.rawAttestationObject ?? Data())
        let clientDataJSON = base64url(data:credentialRegistration.rawClientDataJSON)
        let credentialID = base64url(data:credentialRegistration.credentialID)
        let jsonObject: [String: Any] = [
            "id": credentialID,
            "type": "public-key",
            "rawId": credentialID,
            "response": [
                "clientDataJSON": clientDataJSON,
                "attestationObject": attestationObject
            ]
        ]
        return jsonObject
    }
    
    private func getAssersionObject(credentialAssertion:ASAuthorizationPlatformPublicKeyCredentialAssertion)
    -> [String: Any]{
        let signature = base64url(data:credentialAssertion.signature)
        let credentialID = base64url(data:credentialAssertion.credentialID)
        let authenticatorData = base64url(data:credentialAssertion.rawAuthenticatorData)
        let clientDataJSON = base64url(data:credentialAssertion.rawClientDataJSON)
        let userID = base64url(data:credentialAssertion.userID)
        let jsonObject: [String: Any] = [
            "id": credentialID,
            "type": "public-key",
            "rawId": credentialID,
            "response": [
                "clientDataJSON": clientDataJSON,
                "authenticatorData": authenticatorData,
                "signature": signature,
                "userHandle": userID
            ]
        ]
        return jsonObject
    }
    
    private func fetch(path:String, postbody:Data?) async throws -> [String: Any]{
        print("fetch called with path: "+path)
        let url = URL(string: "https://"+domain+path)!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("XMLHttpRequest", forHTTPHeaderField: "X-Requested-With")
        do{
            request.httpBody  = postbody ?? Data(("").utf8)
            let bodyForLog = String(data:request.httpBody!, encoding: .utf8) ?? ""
            print("fetch body:"+bodyForLog)
            let (data, response) = try await URLSession.shared.data(for:request)
            let object = try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
            return object
        } catch let error {
            print("fetch error")
            throw error
        }
    }
    
    private func base64url(data: Data) -> String{
        var str = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        str.replace(/=+$/, with: "")
        return str
    }
    
    private func base64url(str: String) -> Data{
        var b64 = base64urlToBase64(base64url:str)
        return Data(base64Encoded:b64) ?? Data()
    }
    
    private func base64urlToBase64(base64url: String) -> String {
        var base64 = base64url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }
    
    private func getRandomBytes(size:Int)->Data{
            var bytes = [UInt8](repeating: 0, count: size)
            _ = SecRandomCopyBytes(
                kSecRandomDefault,
                size,
                &bytes
            )
            return Data(bytes)
    }
    
    private func hashPassword(password: String, salt:String) -> String{
        var passwordData = Data(password.utf8)
        guard let saltData = Data(base64Encoded: base64urlToBase64(base64url: salt)) else { return ""}
        passwordData.append(saltData)
        let digest = SHA256.hash(data: passwordData)
        let digestData = Data(digest)
        return base64url(data: digestData)
    }
}
