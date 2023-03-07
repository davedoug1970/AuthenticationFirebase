//
//  AuthService.swift
//  AuthenticationFirebase
//
//  Created by Mindy Douglas on 3/2/23.
//

import Foundation
import FirebaseAuth
import FirebaseFirestore

// singleton

class AuthService {
    
    public static let shared = AuthService()
    private init() {}
    
    /// A method to register the user
    /// - Parameters:
    ///   - userRequest: The users information (email, password, username)
    ///   - completion: A completion with two values...
    ///   - Bool: wasRegistered - determines if the user was registered and saved in the database correctly
    ///   - Error?:  An optional error if Firebase provides one
    
    public func registerUser(with userRequest: RegisterUserRequest, completion: @escaping (Bool, Error?) -> Void) {
        let password = userRequest.password
        let email = userRequest.email
        
        // create user with firebase authentication page
    
        Auth.auth().createUser(withEmail: email, password: password) {
            result, error in
            if let error = error {
                completion(false, error)
                return
            }
          
//            // if no errors we grab result user
//
//            guard let resultUser = result?.user else {
//                    completion(false, nil)
//                    return
//            }
//
//            // save username and email in firestore "users" with user id we get from resultUser
//
//            let db = Firestore.firestore()
//
//            // going into users collection
//            // creating a firestore user and if there is no collection it will create one
//
//            db.collection("users")
//                .document(resultUser.uid)
//                .setData([
//                    "username": username,
//                    "email": email
//                ]) { error in
//                    if let error = error {
//                    completion(false, error)
//                    return
//                }
          
                    // if no errors completion true for registerUser boolean, nil for no errors
                    completion(true, nil)
            //}
        }
    }
    
    public func signIn(with userRequest: LoginUserRequest, completion: @escaping(Error?) -> Void) {
        Auth.auth().signIn(withEmail: userRequest.email, password: userRequest.password) {
            result, error in
            if let error = error {
                completion(error)
                return
            } else {
                completion(nil)
            }
        }
    }
    
    public func signOut(completion: @escaping (Error?) -> Void) {
        do {
            try Auth.auth().signOut()
            completion(nil)
        } catch let error {
              completion(error)
        }
    }
}
