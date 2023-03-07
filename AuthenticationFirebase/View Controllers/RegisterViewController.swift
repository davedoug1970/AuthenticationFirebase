//
//  RegisterController.swift
//  AuthenticationFirebase
//
//  Created by Daesy & Mindy on 2/24/23.
//
// 1 Add packages using Swift Package Manager
// 2 Add repository: https://github.com/firebase-ios-sdk
// 3 Choose firebase authentication library
// 4 connect an app & enable email/password sign in in firebase console
// 5 set up app delegate
// 6 add import statements

import UIKit
import FirebaseAuth
import FirebaseFirestore

class RegisterViewController: UIViewController {
    
    // complete any validation needed for email and password
    // create an account by passing user's email & password to createUser
    // If successful, account data is passed to callback method in result object
    
    @IBOutlet weak var firstNameTextField: UITextField!
    @IBOutlet weak var lastNameTextField: UITextField!
    @IBOutlet weak var emailTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var retypePasswordTextField: UITextField!
    @IBOutlet weak var messageLabel: UILabel!
    
    override func viewDidLoad() {
      super.viewDidLoad()
      
      self.navigationItem.hidesBackButton = true;
    }
    
    func resetFields() {
        firstNameTextField.text = ""
        lastNameTextField.text = ""
        emailTextField.text = ""
        passwordTextField.text = ""
        retypePasswordTextField.text = ""
    }
    
    func checkForEmptyFields() -> Bool {
        if emailTextField.text!.trimmingCharacters(in: .whitespacesAndNewlines) == "" || passwordTextField.text!.trimmingCharacters(in: .whitespacesAndNewlines) == "" ||
            retypePasswordTextField.text!.trimmingCharacters(in: .whitespacesAndNewlines) == "" {
            messageLabel.text = "All fields must be filled in."
            resetFields()
            return true
        } else {
            return false
        }
    }
    
    func checkForMismatchedPasswords() -> Bool {
        let password = passwordTextField.text!.trimmingCharacters(in: .whitespacesAndNewlines)
        let retypePassword = retypePasswordTextField.text!.trimmingCharacters(in: .whitespacesAndNewlines)
        
        if password != retypePassword {
            messageLabel.text = "Passwords do not match."
            resetFields()
           return true
        } else {
            return false
        }
    }
    
    func validateFields() -> Bool {
        let fieldStatus = checkForEmptyFields()
        let passwordStatus = checkForMismatchedPasswords()
        if fieldStatus && passwordStatus == true {
            return false
        }
        return true
    }
        
    func registerUser() {
   
      let userRequest = RegisterUserRequest(email: emailTextField.text!, password: passwordTextField.text!)
      AuthService.shared.registerUser(with: userRequest) { success, error in
        if !success {
          if let newError = error {
            print(newError.localizedDescription)
          }
        } else {
          self.performSegue(withIdentifier: "registered", sender: self)
        }
      }
    }
    

    @IBAction func signInButtonPressed(_ sender: UIButton) {
        let validated = validateFields()
        if validated {
            registerUser()
            }
        }
}
