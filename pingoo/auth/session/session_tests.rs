#[cfg(test)]
mod tests {
    use http::{Request, Response};

    use crate::{
        auth::builder::AuthManagerBuilder,
        config::{AuthConfig, ServiceConfig},
    };

    #[test]
    fn test_session_full_cycle() {
        let auth_manager_builder = AuthManagerBuilder::new(vec![ServiceConfig {
            name: "main".to_string(),
            auth: Some(AuthConfig {
                provider: crate::config::AuthProvider::GitHub,
                client_id: "client_id".to_string(),
                client_secret: "client_secret".to_string(),
                redirect_url: "redirect_uri".to_string(),
            }),
            route: None,
            http_proxy: None,
            r#static: None,
            tcp_proxy: None,
        }]);

        let auth_manager = auth_manager_builder.build().unwrap();
        let session_manager = auth_manager
            .get("main")
            .map(|manager| manager.session_manager())
            .unwrap();

        session_manager.cleanup_expired();

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("Cookie", "__pingoo_oauth_session=1234567890")
            .body(())
            .unwrap();

        let r = session_manager.get_session(&req);
        assert!(r.is_err());

        let created_session =
            session_manager.create_session("123".to_string(), "kz@sample.com".to_string(), "Khaled".to_string(), None);

        assert!(created_session.is_ok());
        let unwrapped_session = created_session.unwrap();

        let encrypted_cookie = session_manager.set_session_cookie(&mut Response::new(()), &unwrapped_session).unwrap();

        let req1 = Request::builder()
            .method("GET")
            .uri("/")
            .header("Cookie", &encrypted_cookie)
            .body(())
            .unwrap();

        assert!(session_manager.get_session(&req1).is_ok());

        let req2 = Request::builder()
            .method("GET")
            .uri("/hello")
            .header("Cookie", &encrypted_cookie)
            .body(())
            .unwrap();

        assert!(session_manager.get_session(&req2).is_ok())
    }
}
