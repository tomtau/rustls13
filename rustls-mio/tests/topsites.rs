// These tests check we can handshake with a selection of
// common hosts.
//
// Rules: only hosts that can really handle the traffic.
// Because we don't go to the same host twice, polite()
// is not needed.
//

#[allow(dead_code)]
mod common;

mod online {
    use super::common::TlsClient;

    fn check(hostname: &str) {
        TlsClient::new(hostname)
            .expect("HTTP/1.[01] ")
            .go()
            .unwrap()
    }

    #[test]
    fn joe() {
        check("jbp.io")
    }

    #[test]
    fn google() {
        check("google.com")
    }

    #[test]
    fn github() {
        check("github.com")
    }

    #[test]
    #[ignore]
    fn aws() {
        // FIXME: TLS 1.3
        check("aws.amazon.com")
    }

    #[test]
    #[ignore]
    fn microsoft() {
        // FIXME: https://www.ssllabs.com/ssltest/analyze.html?d=www.microsoft.com
        check("www.microsoft.com")
    }

    #[test]
    fn wikipedia() {
        check("www.wikipedia.org")
    }

    #[test]
    #[ignore]
    fn twitter() {
        // FIXME: TLS 1.3
        check("twitter.com")
    }

    #[test]
    fn facebook() {
        check("www.facebook.com")
    }

    #[test]
    #[ignore]
    fn baidu() {
        // FIXME: TLS 1.3
        check("www.baidu.com")
    }

    #[test]
    #[ignore]
    fn netflix() {
        // FIXME: TLS 1.3
        check("www.netflix.com")
    }

    #[test]
    #[ignore]
    fn stackoverflow() {
        // FIXME: TLS 1.3
        check("stackoverflow.com")
    }

    #[test]
    fn apple() {
        check("www.apple.com")
    }

}
