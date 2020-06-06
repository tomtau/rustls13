use crate::msgs::enums::{HandshakeType, ProtocolVersion};
use crate::msgs::enums::Compression;
use crate::msgs::enums::{ExtensionType, AlertDescription};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::handshake::{HandshakePayload, SupportedSignatureSchemes};
use crate::msgs::handshake::{ClientHelloPayload, ServerExtension};
use crate::msgs::handshake::{ConvertProtocolNameList, ConvertServerNameList};
use crate::msgs::persist;
use crate::server::{ServerSessionImpl, ServerConfig, ClientHello};
use crate::suites;
use crate::sign;
#[cfg(feature = "logging")]
use crate::log::{trace, debug};
use crate::error::TLSError;
use crate::handshake::check_handshake_message;
use webpki;
#[cfg(feature = "quic")]
use crate::session::Protocol;

use crate::server::common::HandshakeDetails;
use crate::server::tls13;

macro_rules! extract_handshake(
  ( $m:expr, $t:path ) => (
    match $m.payload {
      MessagePayload::Handshake(ref hsp) => match hsp.payload {
        $t(ref hm) => Some(hm),
        _ => None
      },
      _ => None
    }
  )
);

pub type CheckResult = Result<(), TLSError>;
pub type NextState = Box<dyn State + Send + Sync>;
pub type NextStateOrError = Result<NextState, TLSError>;

pub trait State {
    fn check_message(&self, m: &Message) -> CheckResult;
    fn handle(self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError;

    fn export_keying_material(&self,
                              _output: &mut [u8],
                              _label: &[u8],
                              _context: Option<&[u8]>) -> Result<(), TLSError> {
        Err(TLSError::HandshakeNotComplete)
    }

    fn perhaps_write_key_update(&mut self, _sess: &mut ServerSessionImpl) {
    }
}

pub fn incompatible(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
    TLSError::PeerIncompatibleError(why.to_string())
}

fn bad_version(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
    TLSError::PeerIncompatibleError(why.to_string())
}

pub fn illegal_param(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
    TLSError::PeerMisbehavedError(why.to_string())
}

pub fn decode_error(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::DecodeError);
    TLSError::PeerMisbehavedError(why.to_string())
}

pub fn can_resume(sess: &ServerSessionImpl,
                  handshake: &HandshakeDetails,
                  resumedata: &Option<persist::ServerSessionValue>) -> bool {
    // The RFCs underspecify what happens if we try to resume to
    // an unoffered/varying suite.  We merely don't resume in weird cases.
    //
    // RFC 6066 says "A server that implements this extension MUST NOT accept
    // the request to resume the session if the server_name extension contains
    // a different name. Instead, it proceeds with a full handshake to
    // establish a new session."

    if let Some(ref resume) = *resumedata {
        resume.cipher_suite == sess.common.get_suite_assert().suite &&
            (resume.extended_ms == handshake.using_ems ||
             (resume.extended_ms && !handshake.using_ems)) &&
            same_dns_name_or_both_none(resume.sni.as_ref(), sess.sni.as_ref())
    } else {
        false
    }
}

// Require an exact match for the purpose of comparing SNI DNS Names from two
// client hellos, even though a case-insensitive comparison might also be OK.
fn same_dns_name_or_both_none(a: Option<&webpki::DNSName>,
                              b: Option<&webpki::DNSName>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let a: &str = a.as_ref().into();
            let b: &str = b.as_ref().into();
            a == b
        },
        (None, None) => true,
        _ => false,
    }
}

// Changing the keys must not span any fragmented handshake
// messages.  Otherwise the defragmented messages will have
// been protected with two different record layer protections,
// which is illegal.  Not mentioned in RFC.
pub fn check_aligned_handshake(sess: &mut ServerSessionImpl) -> Result<(), TLSError> {
    if !sess.common.handshake_joiner.is_empty() {
        sess.common.send_fatal_alert(AlertDescription::UnexpectedMessage);
        Err(TLSError::PeerMisbehavedError("key epoch or handshake flight with pending fragment".to_string()))
    } else {
        Ok(())
    }
}

pub fn save_sni(sess: &mut ServerSessionImpl,
                sni: Option<webpki::DNSName>) {
    if let Some(sni) = sni {
        // Save the SNI into the session.
        sess.set_sni(sni);
    }
}

#[derive(Default)]
pub struct ExtensionProcessing {
    // extensions to reply with
    pub exts: Vec<ServerExtension>,

    // effects on later handshake steps
    pub send_cert_status: bool,
    pub send_sct: bool,
    pub send_ticket: bool,
}

impl ExtensionProcessing {
    pub fn new() -> Self { Default::default() }

    pub fn process_common(&mut self,
                          sess: &mut ServerSessionImpl,
                          server_key: Option<&mut sign::CertifiedKey>,
                          hello: &ClientHelloPayload,
                          resumedata: Option<&persist::ServerSessionValue>,
                          handshake: &HandshakeDetails)
                          -> Result<(), TLSError> {
        // ALPN
        let our_protocols = &sess.config.alpn_protocols;
        let maybe_their_protocols = hello.get_alpn_extension();
        if let Some(their_protocols) = maybe_their_protocols {
            let their_protocols = their_protocols.to_slices();

            if their_protocols.iter().any(|protocol| protocol.is_empty()) {
                return Err(TLSError::PeerMisbehavedError("client offered empty ALPN protocol"
                    .to_string()));
            }

            sess.alpn_protocol = our_protocols.iter()
                .filter(|protocol| their_protocols.contains(&protocol.as_slice()))
                .nth(0)
                .cloned();
            if let Some(ref selected_protocol) = sess.alpn_protocol {
                debug!("Chosen ALPN protocol {:?}", selected_protocol);
                self.exts.push(ServerExtension::make_alpn(&[selected_protocol]));
            } else {
                // For compatibility, strict ALPN validation is not employed unless targeting QUIC
                #[cfg(feature = "quic")] {
                    if sess.common.protocol == Protocol::Quic && !our_protocols.is_empty() {
                        sess.common.send_fatal_alert(AlertDescription::NoApplicationProtocol);
                        return Err(TLSError::NoApplicationProtocol);
                    }
                }
            }
        }

        #[cfg(feature = "quic")] {
            if sess.common.protocol == Protocol::Quic {
                if let Some(params) = hello.get_quic_params_extension() {
                    sess.common.quic.params = Some(params);
                }

                if let Some(resume) = resumedata {
                    if sess.config.max_early_data_size > 0
                        && hello.early_data_extension_offered()
                        && resume.version == sess.common.negotiated_version.unwrap()
                        && resume.cipher_suite == sess.common.get_suite_assert().suite
                        && resume.alpn.as_ref().map(|x| &x.0) == sess.alpn_protocol.as_ref()
                        && !sess.reject_early_data
                    {
                        self.exts.push(ServerExtension::EarlyData);
                    } else {
                        // Clobber value set in tls13::emit_server_hello
                        sess.common.quic.early_secret = None;
                    }
                }
            }
        }

        let for_resume = resumedata.is_some();
        // SNI
        if !for_resume && hello.get_sni_extension().is_some() {
            self.exts.push(ServerExtension::ServerNameAck);
        }

        if let Some(server_key) = server_key {
            // Send status_request response if we have one.  This is not allowed
            // if we're resuming, and is only triggered if we have an OCSP response
            // to send.
            if !for_resume &&
               hello.find_extension(ExtensionType::StatusRequest).is_some() &&
               server_key.has_ocsp() {
                self.send_cert_status = true;

            }

            if !for_resume &&
               hello.find_extension(ExtensionType::SCT).is_some() &&
               server_key.has_sct_list() {
                self.send_sct = true;

            }
        }

        self.exts.extend(handshake.extra_exts.iter().cloned());

        Ok(())
    }

}

pub struct ExpectClientHello {
    pub handshake: HandshakeDetails,
    pub done_retry: bool,
    pub send_cert_status: bool,
    pub send_sct: bool,
    pub send_ticket: bool,
}

impl ExpectClientHello {
    pub fn new(server_config: &ServerConfig, extra_exts: Vec<ServerExtension>) -> ExpectClientHello {
        let mut ech = ExpectClientHello {
            handshake: HandshakeDetails::new(extra_exts),
            done_retry: false,
            send_cert_status: false,
            send_sct: false,
            send_ticket: false,
        };

        if server_config.verifier.offer_client_auth() {
            ech.handshake.transcript.set_client_auth_enabled();
        }

        ech
    }

    fn into_complete_tls13_client_hello_handling(self) -> tls13::CompleteClientHelloHandling {
        tls13::CompleteClientHelloHandling {
            handshake: self.handshake,
            done_retry: self.done_retry,
            send_cert_status: self.send_cert_status,
            send_sct: self.send_sct,
            send_ticket: self.send_ticket,
        }
    }

}

impl State for ExpectClientHello {
    fn check_message(&self, m: &Message) -> CheckResult {
        check_handshake_message(m, &[HandshakeType::ClientHello])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> NextStateOrError {
        let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();
        // let tls13_enabled = sess.config.supports_version(ProtocolVersion::TLSv1_3);
        trace!("we got a clienthello {:?}", client_hello);

        if !client_hello.compression_methods.contains(&Compression::Null) {
            sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(TLSError::PeerIncompatibleError("client did not offer Null compression"
                .to_string()));
        }

        if client_hello.has_duplicate_extension() {
            return Err(decode_error(sess, "client sent duplicate extensions"));
        }

        // No handshake messages should follow this one in this flight.
        check_aligned_handshake(sess)?;

        // Are we doing TLS1.3?
        let maybe_versions_ext = client_hello.get_versions_extension();
        if let Some(versions) = maybe_versions_ext {
            if versions.contains(&ProtocolVersion::TLSv1_3) {
                sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            } else {
                return Err(bad_version(sess, "TLS1.2 not offered/enabled"));
            }
        } else {
            return Err(bad_version(sess, "Server requires TLS1.3, but client omitted versions ext"));
        }

        if sess.common.negotiated_version == None {
            sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_2); // ???
        }

        // --- Common to TLS1.2 and TLS1.3: ciphersuite and certificate selection.

        // Extract and validate the SNI DNS name, if any, before giving it to
        // the cert resolver. In particular, if it is invalid then we should
        // send an Illegal Parameter alert instead of the Internal Error alert
        // (or whatever) that we'd send if this were checked later or in a
        // different way.
        let sni: Option<webpki::DNSName> = match client_hello.get_sni_extension() {
            Some(sni) => {
                if sni.has_duplicate_names_for_type() {
                    return Err(decode_error(sess, "ClientHello SNI contains duplicate name types"));
                }

                if let Some(hostname) = sni.get_single_hostname() {
                    Some(hostname.into())
                } else {
                    return Err(illegal_param(sess, "ClientHello SNI did not contain a hostname"));
                }
            },
            None => None,
        };

        // We communicate to the upper layer what kind of key they should choose
        // via the sigschemes value.  Clients tend to treat this extension
        // orthogonally to offered ciphersuites (even though, in TLS1.2 it is not).
        // So: reduce the offered sigschemes to those compatible with the
        // intersection of ciphersuites.
        let mut common_suites = sess.config.ciphersuites.clone();
        common_suites.retain(|scs| client_hello.cipher_suites.contains(&scs.suite));

        let mut sigschemes_ext = client_hello.get_sigalgs_extension()
            .cloned()
            .unwrap_or_else(SupportedSignatureSchemes::default);
        sigschemes_ext.retain(|scheme| suites::compatible_sigscheme_for_suites(*scheme, &common_suites));

        let alpn_protocols = client_hello.get_alpn_extension()
            .map(|protos| protos.to_slices());

        // Choose a certificate.
        let certkey = {
            let sni_ref = sni.as_ref().map(webpki::DNSName::as_ref);
            trace!("sni {:?}", sni_ref);
            trace!("sig schemes {:?}", sigschemes_ext);
            trace!("alpn protocols {:?}", alpn_protocols);

            let alpn_slices = match alpn_protocols {
                Some(ref vec) => Some(vec.as_slice()),
                None => None,
            };

            let client_hello = ClientHello::new(sni_ref, &sigschemes_ext, alpn_slices);

            let certkey = sess.config.cert_resolver.resolve(client_hello);
            certkey.ok_or_else(|| {
                sess.common.send_fatal_alert(AlertDescription::AccessDenied);
                TLSError::General("no server certificate chain resolved".to_string())
            })?
        };

        // Reduce our supported ciphersuites by the certificate.
        // (no-op for TLS1.3)
        let suitable_suites = suites::reduce_given_sigalg(&sess.config.ciphersuites,
                                                          certkey.key.algorithm());

        // And version
        let protocol_version = sess.common.negotiated_version.unwrap();
        let suitable_suites = suites::reduce_given_version(&suitable_suites, protocol_version);

        let maybe_ciphersuite = if sess.config.ignore_client_order {
            suites::choose_ciphersuite_preferring_server(&client_hello.cipher_suites, &suitable_suites)
        } else {
            suites::choose_ciphersuite_preferring_client(&client_hello.cipher_suites, &suitable_suites)
        };

        if maybe_ciphersuite.is_none() {
            return Err(incompatible(sess, "no ciphersuites in common"));
        }

        debug!("decided upon suite {:?}", maybe_ciphersuite.as_ref().unwrap());
        sess.common.set_suite(maybe_ciphersuite.unwrap());

        // Start handshake hash.
        let starting_hash = sess.common.get_suite_assert().get_hash();
        if !self.handshake.transcript.start_hash(starting_hash) {
            sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
            return Err(TLSError::PeerIncompatibleError("hash differed on retry"
                .to_string()));
        }

        // Save their Random.
        client_hello.random.write_slice(&mut self.handshake.randoms.client);

        // if sess.common.is_tls13() {
            return self.into_complete_tls13_client_hello_handling()
                .handle_client_hello(sess, sni, certkey, &m);
        // }

    }
}
