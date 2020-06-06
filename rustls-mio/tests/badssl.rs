// These tests use the various test servers run by Google
// at badssl.com.  To be polite they sleep 1 second before
// each test.
//

#[allow(dead_code)]
mod common;

mod online {
    use super::common::{TlsClient, polite};

    fn connect(hostname: &str) -> TlsClient {
        TlsClient::new(hostname)
    }

    #[test]
    fn no_cbc() {
        polite();
        connect("cbc.badssl.com")
            .fails()
            .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
            .go()
            .unwrap();
    }

    #[test]
    fn no_rc4() {
        polite();
        connect("rc4.badssl.com")
            .fails()
            .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn expired() {
        // FIXME: no TLS 1.3
        polite();
        connect("expired.badssl.com")
            .fails()
            .expect(r"TLS error: WebPKIError\(CertExpired\)")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn wrong_host() {
        // FIXME: TLS 1.3
        polite();
        connect("wrong.host.badssl.com")
            .fails()
            .expect(r"TLS error: WebPKIError\(CertNotValidForName\)")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn self_signed() {
        // FIXME: TLS 1.3
        polite();
        connect("self-signed.badssl.com")
            .fails()
            .expect(r"TLS error: WebPKIError\((UnknownIssuer|CertExpired)\)")
            .go()
            .unwrap();
    }

    #[test]
    fn no_dh() {
        polite();
        connect("dh2048.badssl.com")
            .fails()
            .expect(r"TLS error: AlertReceived\(HandshakeFailure\)")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn mozilla_old() {
        polite();
        connect("mozilla-old.badssl.com")
            .expect("<title>mozilla-old.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn mozilla_inter() {
        polite();
        connect("mozilla-intermediate.badssl.com")
            .expect("<title>mozilla-intermediate.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn mozilla_modern() {
        // FIXME: https://github.com/chromium/badssl.com/issues/424
        polite();
        connect("mozilla-modern.badssl.com")
            .expect("<title>mozilla-modern.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn sha256() {
        // FIXME: TLS 1.3
        polite();
        connect("sha256.badssl.com")
            .expect("<title>sha256.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn too_many_sans() {
        // FIXME: TLS 1.3
        polite();
        connect("10000-sans.badssl.com")
            .fails()
            .expect(r"TLS error: CorruptMessagePayload\(Handshake\)")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn rsa8192() {
        // FIXME: tls 1.3
        polite();
        connect("rsa8192.badssl.com")
            .expect("<title>rsa8192.badssl.com</title>")
            .go()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn sha1_2016() {
        polite();
        connect("sha1-2016.badssl.com")
            .fails()
            .expect(r"TLS error: WebPKIError\(CertExpired\)")
            .go()
            .unwrap();
    }

    #[cfg(feature = "dangerous_configuration")]
    mod danger {
        #[test]
        #[ignore]
        fn self_signed() {
            // FIXME: TLS 1.3
            super::polite();
            super::connect("self-signed.badssl.com")
                .insecure()
                .expect("<title>self-signed.badssl.com</title>")
                .go()
                .unwrap();
        }
    }
}
