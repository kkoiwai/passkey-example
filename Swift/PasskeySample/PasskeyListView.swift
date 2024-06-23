//
//  PasskeyListView.swift
//  PasskeySample
//
//  Created by Kosuke Koiwai on 2024/06/02.
//

import SwiftUI

struct PasskeyListView: View {
    @State private var passkeys: [Passkey] = []
    @State private var isLoading = true
    @StateObject private var passkeyService = PasskeyService()

    var body: some View {
        VStack {
            Text("Available Passkeys")
                .font(.largeTitle)
                .padding()

            if isLoading {
                ProgressView("Loading...")
                    .progressViewStyle(CircularProgressViewStyle())
                    .padding()
            } else {
                List {
                    ForEach(passkeys) { passkey in
                        VStack(alignment: .leading){
                            Text(passkey.credId)
                            Text(passkey.publicKey)
                                .font(.subheadline)
                            Text(passkey.created)
                                .font(.subheadline)
                        }
                    }
                    .onDelete(perform: deletePasskey)
                }
                .refreshable {
                                fetchPasskeys()
                            }
            }
        }
        .onAppear {
            fetchPasskeys()
        }
    }

    private func fetchPasskeys() {
        Task{
            let fetchedPasskeys = await passkeyService.fetchPasskeys()
            await MainActor.run {
                self.passkeys  = fetchedPasskeys
                self.isLoading = false
            }
        }
           
    }

    private func deletePasskey(at offsets: IndexSet) {
        if let index = offsets.first {
            let credId =  passkeys[index].credId
            passkeys.remove(atOffsets: offsets)
            passkeyService.removeKey(credId:credId)
        }
        
    }
}

#Preview {
    PasskeyListView()
}
