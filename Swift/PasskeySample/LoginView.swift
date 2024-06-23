//
//  LoginView.swift
//  PasskeySample
//
//  Created by Kosuke Koiwai on 2024/06/02.
//

import SwiftUI

struct LoginView: View {
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var progressMessage: String = ""
    @State private var isProcessing: Bool = false
    @State private var isCreateAccountMode: Bool = false
    @State private var showAlert: Bool = false
    @State private var alertMessage: String = ""
    @StateObject private var passkeyService = PasskeyService()

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if isCreateAccountMode{
                    Text("Register")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                }else{
                    Text("Login")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                }

                TextField("Username", text: $username)
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(5.0)
                    .textContentType(.username)
                    .keyboardType(.emailAddress)
                    .disabled(isProcessing || passkeyService.isLoggedIn)
                    .navigationDestination(
                         isPresented:$passkeyService.isLoggedIn) {
                             PasskeyListView().onDisappear(perform: {
                                 passkeyService.signout()
                                 isCreateAccountMode = false
                             })
                         }
//                     .task {
//                         passkeyService.authenticateWithPasskey(autofill: true)
//                     }
                
                if isCreateAccountMode{
                    SecureField("Password", text: $password)
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(5.0)
                        .textContentType(.newPassword)
                        .disabled(isProcessing || passkeyService.isLoggedIn)
                }else{
                    SecureField("Password", text: $password)
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(5.0)
                        .textContentType(.password)
                        .disabled(isProcessing || passkeyService.isLoggedIn)
                }
                
                if isProcessing {
                    ProgressView(progressMessage)
                        .progressViewStyle(CircularProgressViewStyle())
                        .padding()
                } else {
                    if isCreateAccountMode{
                        Button(action: {
                            progressMessage = "Registering..."
                            isProcessing = true
                            passkeyService.register(username: username, password: password)
                        }) {
                            Text("Register")
                                .font(.headline)
                                .foregroundColor(.white)
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(Color.blue)
                                .cornerRadius(10.0)
                        }
                        
                        Button(action: {
                            isCreateAccountMode.toggle()
                        }) {
                            Text("Login to an existing account")
                                .foregroundColor(.blue)
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(Color.clear)
                                .cornerRadius(10.0)
                        }
                    }
                    else{
                        Button(action: {
                            progressMessage = "Authenticating..."
                            isProcessing = true
                            
                            passkeyService.authenticateWithPassword(username: username, password: password)
                            password = ""
                        }) {
                            Text("Login with Password")
                                .font(.headline)
                                .foregroundColor(.white)
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(Color.blue)
                                .cornerRadius(10.0)
                        }
                        
                        Button(action: {
                            progressMessage = "Authenticating..."
                            isProcessing = true
                            
                            passkeyService.authenticateWithPasskey()
                        }) {
                            Text("Login with Passkey")
                                .font(.headline)
                                .foregroundColor(.white)
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(Color.blue)
                                .cornerRadius(10.0)
                        }
                        
                        Button(action:{
                            isCreateAccountMode.toggle()
                        }) {
                            Text("Register a new account")
                                .foregroundColor(.blue)
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(Color.clear)
                                .cornerRadius(10.0)
                        }
                    }
                }

                
            }
            .padding()
            
            .alert(isPresented: $showAlert) {
                Alert(
                    title: Text(passkeyService.processType + " Error"),
                    message: Text(alertMessage),
                    dismissButton: .default(
                        Text("OK"),
                        action: { 
                            print("OK")
                        })
                )
            }
            
            .onChange(of: passkeyService.errorMessage) {
                if let error =  passkeyService.errorMessage {
                    passkeyService.errorMessage = nil
                    alertMessage = error
                    showAlert = true
                    isProcessing = false
                }
            }
            .onChange(of: passkeyService.isLoggedIn) {
                if passkeyService.isLoggedIn {
                    isProcessing = false
                }
            }
        }
    }
}



#Preview {
    LoginView()
}
