//
//  SceneDelegate.swift
//  AuthenticationFirebase
//
//  Created by Mindy Douglas on 2/24/23.
//

import UIKit
import FirebaseAuth

class SceneDelegate: UIResponder, UIWindowSceneDelegate {

    var window: UIWindow?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
//        self.setupWindow(with: scene)

    }
    
//    private func setupWindow(with scene: UIScene) {
//        guard let windowScene = (scene as? UIWindowScene) else { return }
//        let window = UIWindow(windowScene: windowScene)
//        self.window = window
//        self.window?.makeKeyAndVisible()
//    }
//
//    public func checkAuthentication() {
//        if Auth.auth().currentUser == nil {
//            // go to sign in screen
//            let vc = SignInViewController()
//            let nav = UINavigationController(rootViewController: vc)
//            nav.modalPresentationStyle = .fullScreen
//            self.window?.rootViewController = nav
//        } else {
//            // go to home screen
//            let vc = HomeViewController()
//            let nav = UINavigationController(rootViewController: vc)
//            nav.modalPresentationStyle = .fullScreen
//            self.window?.rootViewController = nav
//        }
//    }
//
//    private func goToController(with viewController: UIViewController) {
//        DispatchQueue.main.async { [weak self] in
//            UIView.animate(withDuration: 0.25) {
//                self?.window?.layer.opacity = 0
//
//            } completion: { [weak self] _ in
//                let nav = UINavigationController(rootViewController: viewController)
//                nav.modalPresentationStyle = .fullScreen
//                self?.window?.rootViewController = nav
//            }
//        }
//    }
}

