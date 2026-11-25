//! End to end: the real API, the real SMTP client, the real SMTP listener,
//! and the real webhook poster, all on loopback. DNS is the only thing that
//! leaves the machine, and every name it asks about does not exist.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use mail_auth::MessageAuthenticator;
use mail_send::smtp::message::Message;
use mail_send::SmtpClientBuilder;
use tokio::net::TcpListener;

use base64::Engine;

use crate::app::App;
use crate::config::Config;
use crate::db::{tempdir::Dir, Db};
use crate::deliver::{self, Outcome};
use crate::dkim::DkimKeys;
use crate::util::sha256_hex;
use crate::{api, smtpd, webhook};

const API_KEY: &str = "ms_test_key";
const HOOK_SECRET: &str = "hook-secret-hook-secret-hook";
const PASSWORD: &str = "sloth-submission-password";

type Hits = Arc<Mutex<Vec<(HeaderMap, String)>>>;

async fn hook(State(hits): State<Hits>, headers: HeaderMap, body: String) -> &'static str {
    hits.lock().unwrap().push((headers, body));
    "ok"
}

struct Harness {
    app: Arc<App>,
    api_url: String,
    smtp_port: u16,
    submission_port: u16,
    hits: Hits,
    _dir: Dir,
}

async fn harness() -> Harness {
    crate::tls::install_crypto_provider();
    let dir = Dir::new("e2e");
    let smtp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtp_port = smtp.local_addr().unwrap().port();
    let submission = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let submission_port = submission.local_addr().unwrap().port();
    let hook_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_port = hook_listener.local_addr().unwrap().port();
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_port = api_listener.local_addr().unwrap().port();

    let cfg = Config::parse(&format!(
        r#"
hostname = "mail.sloth.test"
tls = false
data_dir = "{data}"
srs_secret = "srs-secret-srs-secret-srs-secret"
mx_override = "127.0.0.1:{smtp_port}"
send_rate_per_second = 100

[[site]]
name = "party"
api_keys = ["{key_hash}"]
webhook_url = "http://127.0.0.1:{hook_port}/hook"
webhook_secret = "{hook_secret}"
domains = ["sloth.test", "quiet.test"]

[[site]]
name = "other"
webhook_url = "http://127.0.0.1:{hook_port}/hook"
webhook_secret = "{hook_secret}"
domains = ["other.test"]

[[domain]]
name = "other.test"
inbound_webhook = true

[[domain]]
name = "sloth.test"
inbound_webhook = true
[domain.senders]
paul = {{ name = "Paul Sloth", reply_to = "paul@gmail.example", password = "sha256:{password_hash}" }}
[domain.forward]
paul = ["paul@gmail.example"]

[[domain]]
name = "quiet.test"
[domain.forward]
someone = ["someone@gmail.example"]
dmarc = []
"#,
        data = dir.path.display(),
        key_hash = sha256_hex(API_KEY.as_bytes()),
        hook_secret = HOOK_SECRET,
        password_hash = sha256_hex(PASSWORD.as_bytes()),
    ))
    .unwrap();
    let key_path = crate::dkim::key_path(&cfg, "sloth.test", "sloth");
    crate::dkim::generate_if_missing(&key_path).unwrap();

    let db = Db::open(&cfg.db_path()).await.unwrap();
    let dkim = DkimKeys::load(&cfg).unwrap();
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let app = App::new(cfg, db, dkim, resolver);

    tokio::spawn(smtpd::serve(app.clone(), None, smtp));
    tokio::spawn(smtpd::serve_submission(app.clone(), None, submission));
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let hook_app = Router::new().route("/hook", post(hook)).with_state(hits.clone());
    tokio::spawn(async move { axum::serve(hook_listener, hook_app).await.unwrap() });
    let router = api::router(app.clone());
    tokio::spawn(async move { axum::serve(api_listener, router).await.unwrap() });

    Harness {
        app,
        api_url: format!("http://127.0.0.1:{api_port}"),
        smtp_port,
        submission_port,
        hits,
        _dir: dir,
    }
}

/// Code, enhanced status and text of a rejection.
fn rejection(err: mail_send::Error) -> (u16, [u8; 3], String) {
    match err {
        mail_send::Error::UnexpectedReply(r) => (r.code, r.esc, r.message),
        other => panic!("not an SMTP rejection: {other:?}"),
    }
}

async fn smtp_submit(port: u16, from: &str, to: &str, body: &[u8]) -> Result<(), mail_send::Error> {
    smtp_submit_as(port, None, from, &[to], body).await
}

/// Sends through a listener, logging in first when given credentials.
async fn smtp_submit_as(port: u16, login: Option<(&str, &str)>, from: &str, to: &[&str], body: &[u8]) -> Result<(), mail_send::Error> {
    let mut builder = SmtpClientBuilder::new("127.0.0.1", port)
        .unwrap()
        .implicit_tls(false)
        .helo_host("client.sloth.test");
    if let Some(creds) = login {
        builder = builder.credentials(creds);
    }
    let mut client = builder.connect_plain().await?;
    client.send(Message::new(from, to.to_vec(), body)).await?;
    let _ = client.quit().await;
    Ok(())
}

#[tokio::test]
async fn send_forward_bounce_and_webhooks() {
    let h = harness().await;
    let http = reqwest::Client::new();

    // ---- a site sends to a mailbox at its own domain ------------------------
    let resp = http
        .post(format!("{}/v1/send", h.api_url))
        .bearer_auth(API_KEY)
        .json(&serde_json::json!({
            "from": "paul@sloth.test",
            "to": [{"email": "paul@sloth.test", "name": "Paul", "vars": {"tag": "<x>"}}],
            "subject": "Hello {{name}}",
            "text": "Hi {{name}} {{tag}}",
            "html": "<p>Hi {{name}} {{tag}}</p>",
            "headers": {"List-Unsubscribe": "<https://sloth.test/u?e={{email}}>"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "{}", resp.text().await.unwrap());
    let sent: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(sent["queued"].as_array().unwrap().len(), 1);
    let id = sent["queued"][0]["id"].as_str().unwrap().to_string();

    // A wrong key and a foreign domain are refused.
    let r = http
        .post(format!("{}/v1/send", h.api_url))
        .bearer_auth("nope")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = http
        .post(format!("{}/v1/send", h.api_url))
        .bearer_auth(API_KEY)
        .json(&serde_json::json!({"from": "x@other.test", "to": ["a@b.co"], "subject": "s", "text": "t"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // ---- the outbox delivers it over SMTP into our own listener ----------------
    let m = h.app.db.claim_due_message().await.unwrap().unwrap();
    assert_eq!(m.id, id);
    let raw = String::from_utf8_lossy(&m.raw).to_string();
    assert!(raw.contains("Subject: Hello Paul"));
    assert!(raw.contains("Hi Paul <x>"), "text body keeps raw vars");
    assert!(raw.contains("Hi Paul &lt;x&gt;"), "html body escapes vars");
    assert!(raw.contains("List-Unsubscribe: <https://sloth.test/u?e=paul@sloth.test>"));
    assert!(raw.contains("Reply-To: <paul@gmail.example>") || raw.contains("Reply-To: paul@gmail.example"));
    let outcome = deliver::deliver(&h.app, &m).await;
    let Outcome::Sent(reply) = outcome else {
        panic!("expected Sent, got {outcome:?}")
    };
    assert!(reply.contains("250 2.0.0 ok: queued as"), "{reply}");
    deliver::record(&h.app, &m, Outcome::Sent(reply)).await;
    assert_eq!(h.app.db.get_message(&id).await.unwrap().unwrap().status, "sent");

    // ---- the listener forwarded it, sealed and SRS-rewritten -----------------
    let fwd = h.app.db.claim_due_message().await.unwrap().unwrap();
    assert_eq!(fwd.kind, "forward");
    assert_eq!(fwd.rcpt_to, "paul@gmail.example");
    assert!(fwd.mail_from.starts_with("SRS0="), "{}", fwd.mail_from);
    assert!(fwd.mail_from.ends_with("@sloth.test"));
    let fraw = String::from_utf8_lossy(&fwd.raw).to_string();
    assert!(fraw.starts_with("Received: from mail.sloth.test ([127.0.0.1])"));
    assert!(fraw.contains("ARC-Seal: i=1;"));
    assert!(fraw.contains("ARC-Message-Signature: i=1;"));
    assert!(fraw.contains("ARC-Authentication-Results: i=1; mail.sloth.test"));
    assert!(fraw.contains("Authentication-Results: mail.sloth.test"));
    assert!(fraw.contains("DKIM-Signature: v=1; a=rsa-sha256;"));
    assert!(fraw.contains("Hi Paul <x>"));
    // Forwarding it lands back on us, and we are not a relay for gmail.example.
    let outcome = deliver::deliver(&h.app, &fwd).await;
    let Outcome::Failed(err) = outcome else {
        panic!("expected Failed, got {outcome:?}")
    };
    assert!(err.contains("550 5.7.1 relay not permitted"), "{err}");
    deliver::record(&h.app, &fwd, Outcome::Failed(err)).await;

    // ---- a bounce for the original message comes back ---------------------------
    let dsn = format!(
        "From: MAILER-DAEMON@gmail.example\r\nTo: bounce+{id}@sloth.test\r\nSubject: Undelivered Mail\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n--b\r\n\
         Content-Type: message/delivery-status\r\n\r\nFinal-Recipient: rfc822; paul@sloth.test\r\n\
         Action: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 user unknown\r\n--b--\r\n"
    );
    smtp_submit(h.smtp_port, "", &format!("bounce+{id}@sloth.test"), dsn.as_bytes())
        .await
        .unwrap();
    let bounced = h.app.db.get_message(&id).await.unwrap().unwrap();
    assert_eq!(bounced.status, "bounced");
    assert_eq!(bounced.last_error.as_deref(), Some("smtp; 550 5.1.1 user unknown"));
    assert!(h.app.db.is_suppressed("paul@sloth.test").await.unwrap());

    // ---- a bounce for the forward unwraps the SRS address -----------------------
    let srs_local = fwd.mail_from.split('@').next().unwrap().to_string();
    smtp_submit(h.smtp_port, "", &format!("{srs_local}@sloth.test"), b"Subject: bounce\r\n\r\nx\r\n")
        .await
        .unwrap();
    let ret = h.app.db.claim_due_message().await.unwrap().unwrap();
    assert_eq!(ret.kind, "forward");
    assert_eq!(ret.rcpt_to, format!("bounce+{id}@sloth.test"));
    assert_eq!(ret.mail_from, "");

    // ---- bad recipients are refused before DATA --------------------------------
    let err = smtp_submit(h.smtp_port, "a@b.test", "nobody@quiet.test", b"Subject: x\r\n\r\nx\r\n")
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (550, [5, 1, 1], "no such user".to_string()));
    let err = smtp_submit(h.smtp_port, "a@b.test", "x@elsewhere.test", b"Subject: x\r\n\r\nx\r\n")
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (550, [5, 7, 1], "relay not permitted".to_string()));
    let err = smtp_submit(h.smtp_port, "a@b.test", "SRS0=bad=AA=x.test=y@sloth.test", b"x")
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (550, [5, 1, 1], "no such user".to_string()));

    // ---- the suppressed address is skipped on the next send ---------------------
    let resp = http
        .post(format!("{}/v1/send", h.api_url))
        .bearer_auth(API_KEY)
        .json(&serde_json::json!({"from": "paul@sloth.test", "to": ["paul@sloth.test", "not-an-address"], "subject": "s", "text": "t", "transactional": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["queued"].as_array().unwrap().len(), 0);
    assert_eq!(v["skipped"][0]["reason"], "suppressed");
    // A list send without a way off the list is refused outright.
    let r = http
        .post(format!("{}/v1/send", h.api_url))
        .bearer_auth(API_KEY)
        .json(&serde_json::json!({"from": "paul@sloth.test", "to": ["a@y.test", "b@y.test"], "subject": "s", "text": "t"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("List-Unsubscribe"));
    assert_eq!(v["skipped"][1]["reason"], "invalid address");

    // ---- lookups ----------------------------------------------------------------
    let v: serde_json::Value = http
        .get(format!("{}/v1/messages/{id}", h.api_url))
        .bearer_auth(API_KEY)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["status"], "bounced");
    let v: serde_json::Value = http
        .get(format!("{}/v1/batches/{}", h.api_url, sent["batch_id"].as_str().unwrap()))
        .bearer_auth(API_KEY)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["counts"]["bounced"], 1);
    let v: serde_json::Value = http
        .get(format!("{}/healthz", h.api_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["ok"], true);

    // ---- webhooks: sent, received, bounced, each signed --------------------------
    let n = webhook::deliver_due(&h.app).await.unwrap();
    assert_eq!(n, 3);
    let hits = h.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 3);
    let mut types = Vec::new();
    for (headers, body) in &hits {
        let sig = headers.get("x-sloth-signature").unwrap().to_str().unwrap();
        let t: i64 = sig.split(',').next().unwrap().trim_start_matches("t=").parse().unwrap();
        assert_eq!(sig, webhook::signature(HOOK_SECRET, t, body), "signature verifies");
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(headers.get("x-sloth-event").unwrap().to_str().unwrap(), v["type"].as_str().unwrap());
        types.push(v["type"].as_str().unwrap().to_string());
        match v["type"].as_str().unwrap() {
            "message.sent" => assert_eq!(v["data"]["message_id"], id),
            "message.bounced" => assert_eq!(v["data"]["detail"], "smtp; 550 5.1.1 user unknown"),
            "mail.received" => {
                assert_eq!(v["data"]["subject"], "Hello Paul");
                assert_eq!(v["data"]["from"]["email"], "paul@sloth.test");
                assert_eq!(v["data"]["to"][0], "paul@sloth.test");
                assert!(v["data"]["text"].as_str().unwrap().contains("Hi Paul <x>"));
                assert!(v["data"]["html"].as_str().unwrap().contains("Hi Paul &lt;x&gt;"));
                assert_eq!(v["data"]["auth"]["tls"], false);
                assert_eq!(v["data"]["auth"]["arc"], "none");
                assert!(v["data"]["headers"].as_array().unwrap().iter().any(|h| h[0] == "DKIM-Signature"));
            }
            other => panic!("unexpected event {other}"),
        }
    }
    types.sort();
    assert_eq!(types, ["mail.received", "message.bounced", "message.sent"]);
    assert_eq!(webhook::deliver_due(&h.app).await.unwrap(), 0, "delivered events are not resent");
}

// hosts which accept the connection but then send no data (example: broken ELB)
async fn blackhole_hosts(n: usize) -> Vec<(String, u16)> {
    let mut hosts = Vec::new();
    for _ in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        hosts.push(("127.0.0.1".to_string(), l.local_addr().unwrap().port()));
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
    }
    hosts
}

/// The outbox is processed by a single worker and walks the receiving 
// domain's MXs until it finds a working one. If they broken (or malicious)
// each ties the worker up for the connect timeout duration
//
// Added as POC, run with:
//
// cargo test --lib poc_mx -- --ignored --nocapture
#[tokio::test]
#[ignore = "minutes: each blackholed host burns a real connect timeout"]
async fn poc_mx_fanout_stalls_the_whole_outbox() {
    let h = harness().await;
    let m = crate::db::MessageRow {
        id: "poc".into(),
        site: "party".into(),
        batch_id: "poc".into(),
        kind: "forward".into(),
        domain: "sloth.test".into(),
        mail_from: "bounce+poc@sloth.test".into(),
        rcpt_to: "victim@evil.test".into(),
        from_header: "a@b.test".into(),
        subject: "poc".into(),
        raw: b"Subject: poc\r\n\r\nx\r\n".to_vec(),
        status: "sending".into(),
        attempts: 0,
        next_attempt_at: None,
        last_error: None,
        created_at: crate::util::now(),
        updated_at: crate::util::now(),
        sent_at: None,
    };

    // What one unreachable host costs us.
    let one = blackhole_hosts(1).await;
    let start = std::time::Instant::now();
    let outcome = deliver::try_hosts(&h.app, one, &m, &m.raw).await;
    let per_host = start.elapsed();
    println!("1 blackholed MX host:  stalled {per_host:?} -> {outcome:?}");
    assert!(matches!(outcome, Outcome::Deferred(_)), "{outcome:?}");

    // Now twenty, through the same path a real MX answer takes. Uncapped
    // that is twenty times the above; the cap is what keeps it a constant.
    let many = blackhole_hosts(20).await;
    let names: Vec<String> = many.iter().map(|(h, p)| format!("{h}:{p}")).collect();
    let hosts = deliver::mx_hosts(names.iter(), "evil.test").unwrap();
    let hosts: Vec<(String, u16)> = hosts
        .iter()
        .map(|(hp, _)| {
            let (host, port) = hp.rsplit_once(':').unwrap();
            (host.to_string(), port.parse().unwrap())
        })
        .collect();
    let start = std::time::Instant::now();
    let outcome = deliver::try_hosts(&h.app, hosts, &m, &m.raw).await;
    let total = start.elapsed();
    println!("20 blackholed MX hosts: stalled {total:?} -> {outcome:?}");
    assert!(
        total < per_host * 8,
        "20 MX records cost {total:?}, roughly {:.0}x one host",
        total.as_secs_f64() / per_host.as_secs_f64()
    );
}

#[tokio::test]
async fn oversized_and_malformed_input_is_refused() {
    let h = harness().await;
    // Talk raw SMTP to check the size limit and error handling.
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", h.smtp_port)).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut l = String::new();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("220"), "{l}");
    w.write_all(b"BOGUS\r\n").await.unwrap();
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("500"), "{l}");
    w.write_all(b"MAIL FROM:<a@b.test>\r\n").await.unwrap();
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("503"), "{l}");
    w.write_all(b"EHLO x\r\n").await.unwrap();
    loop {
        l.clear();
        r.read_line(&mut l).await.unwrap();
        if l.starts_with("250 ") {
            break;
        }
    }
    w.write_all(format!("MAIL FROM:<a@b.test> SIZE={}\r\n", 100 * 1024 * 1024).as_bytes())
        .await
        .unwrap();
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("552"), "{l}");
    w.write_all(b"MAIL FROM:<a@b.test>\r\nRCPT TO:<paul@sloth.test>\r\nDATA\r\n")
        .await
        .unwrap();
    for want in ["250", "250", "354"] {
        l.clear();
        r.read_line(&mut l).await.unwrap();
        assert!(l.starts_with(want), "wanted {want}, got {l}");
    }
    w.write_all(b"Subject: pipelined\r\n\r\nbody\r\n.\r\nQUIT\r\n").await.unwrap();
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("250 2.0.0 ok: queued as"), "{l}");
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("221"), "{l}");
    let fwd = h.app.db.claim_due_message().await.unwrap().unwrap();
    assert_eq!(fwd.rcpt_to, "paul@gmail.example");
    assert!(String::from_utf8_lossy(&fwd.raw).contains("Subject: pipelined"));
}

#[tokio::test]
async fn an_empty_forward_list_keeps_the_mail() {
    let h = harness().await;
    let report = b"From: noreply-dmarc-support@google.example\r\nSubject: Report domain: quiet.test\r\n\r\nzipped xml\r\n";
    smtp_submit(h.smtp_port, "noreply-dmarc-support@google.example", "dmarc@quiet.test", report)
        .await
        .unwrap();
    assert!(h.app.db.claim_due_message().await.unwrap().is_none(), "nothing is forwarded");
    let (action, raw) = h.app.db.inbound_by_subject("Report domain: quiet.test").await.unwrap().unwrap();
    assert_eq!(action, "kept");
    assert!(String::from_utf8_lossy(&raw.unwrap()).contains("zipped xml"));

    // Cleanup drops the bodies of old inbound mail, but a kept body is the only copy.
    smtp_submit(
        h.smtp_port,
        "a@b.test",
        "someone@quiet.test",
        b"Subject: passing through\r\n\r\nx\r\n",
    )
    .await
    .unwrap();
    h.app.db.cleanup("1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z").await.unwrap();
    let (_, raw) = h.app.db.inbound_by_subject("Report domain: quiet.test").await.unwrap().unwrap();
    assert!(raw.is_some(), "kept mail keeps its body");
    let (action, raw) = h.app.db.inbound_by_subject("passing through").await.unwrap().unwrap();
    assert_eq!(action, "forward:someone@gmail.example");
    assert!(raw.is_none(), "forwarded mail's body is dropped");
}

#[tokio::test]
async fn gmail_sends_as_the_domain() {
    let h = harness().await;
    let login = Some(("paul@sloth.test", PASSWORD));
    let good = b"From: Paul Sloth <paul@sloth.test>\r\nTo: friend@elsewhere.test\r\nBcc: secret@elsewhere.test\r\nSubject: Re: the party\r\n\r\nSee you there.\r\n";

    // ---- the submission port refuses everything but a logged-in sender -------
    let err = smtp_submit_as(h.submission_port, None, "paul@sloth.test", &["friend@elsewhere.test"], good)
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (530, [5, 7, 0], "authentication required".to_string()));
    let err = smtp_submit_as(
        h.submission_port,
        Some(("paul@sloth.test", "wrong")),
        "paul@sloth.test",
        &["friend@elsewhere.test"],
        good,
    )
    .await
    .unwrap_err();
    let mail_send::Error::AuthenticationFailed(r) = err else {
        panic!("expected an auth failure, got {err:?}")
    };
    assert_eq!(r.code, 535);
    let err = smtp_submit_as(
        h.submission_port,
        Some(("nobody@sloth.test", PASSWORD)),
        "nobody@sloth.test",
        &["friend@elsewhere.test"],
        good,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, mail_send::Error::AuthenticationFailed(_)), "{err:?}");
    // Port 25 never offers AUTH at all.
    let err = smtp_submit_as(h.smtp_port, login, "paul@sloth.test", &["friend@elsewhere.test"], good)
        .await
        .unwrap_err();
    assert!(matches!(err, mail_send::Error::UnsupportedAuthMechanism), "{err:?}");

    // ---- logged in, the envelope and the From must be the login ----------------
    let err = smtp_submit_as(h.submission_port, login, "other@sloth.test", &["friend@elsewhere.test"], good)
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (553, [5, 7, 1], "sender does not match login".to_string()));
    let forged = b"From: Someone Else <other@sloth.test>\r\nSubject: x\r\n\r\nx\r\n";
    let err = smtp_submit_as(h.submission_port, login, "paul@sloth.test", &["friend@elsewhere.test"], forged)
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (550, [5, 7, 1], "From must match login".to_string()));
    let err = smtp_submit_as(h.submission_port, login, "paul@sloth.test", &["not-an-address"], good)
        .await
        .unwrap_err();
    assert_eq!(rejection(err).0, 501);
    // The login's address hiding behind another From, as a second header or a second mailbox, is still a forgery.
    for forged in [
        &b"From: The Boss <boss@elsewhere.test>\r\nFrom: Paul Sloth <paul@sloth.test>\r\nSubject: x\r\n\r\nx\r\n"[..],
        &b"From: Paul Sloth <paul@sloth.test>\r\nFrom: The Boss <boss@elsewhere.test>\r\nSubject: x\r\n\r\nx\r\n"[..],
        &b"From: Paul Sloth <paul@sloth.test>, The Boss <boss@elsewhere.test>\r\nSubject: x\r\n\r\nx\r\n"[..],
    ] {
        let err = smtp_submit_as(h.submission_port, login, "paul@sloth.test", &["friend@elsewhere.test"], forged)
            .await
            .unwrap_err();
        assert_eq!(rejection(err), (550, [5, 7, 1], "From must match login".to_string()));
    }
    assert!(
        h.app.db.claim_due_message().await.unwrap().is_none(),
        "a refused submission queues nothing"
    );

    // ---- a real reply goes out as a signed send to anyone ----------------------
    smtp_submit_as(
        h.submission_port,
        login,
        "PAUL@sloth.test",
        &["friend@elsewhere.test", "paul@sloth.test"],
        good,
    )
    .await
    .unwrap();
    let a = h.app.db.claim_due_message().await.unwrap().unwrap();
    let b = h.app.db.claim_due_message().await.unwrap().unwrap();
    let (foreign, local) = if a.rcpt_to == "friend@elsewhere.test" { (a, b) } else { (b, a) };
    assert_eq!(foreign.rcpt_to, "friend@elsewhere.test");
    assert_eq!(local.rcpt_to, "paul@sloth.test");
    assert_eq!(foreign.batch_id, local.batch_id);
    for m in [&foreign, &local] {
        assert_eq!(m.kind, "send");
        assert_eq!(m.site, "party");
        assert_eq!(m.domain, "sloth.test");
        assert_eq!(m.mail_from, format!("bounce+{}@sloth.test", m.id));
        assert_eq!(m.from_header, "Paul Sloth <paul@sloth.test>");
        assert_eq!(m.subject, "Re: the party");
        let raw = String::from_utf8_lossy(&m.raw).to_string();
        assert!(!raw.contains("secret@elsewhere.test"), "Bcc must be stripped: {raw}");
        assert!(raw.starts_with("Date: "), "{raw}");
        assert!(raw.contains(&format!("Message-ID: <{}@sloth.test>", m.batch_id)), "{raw}");
        assert!(raw.contains("To: friend@elsewhere.test\r\n"));
        assert!(raw.contains("Subject: Re: the party\r\n\r\nSee you there.\r\n"), "{raw:?}");
    }
    // Delivered through the loopback MX it is DKIM-signed like any other send.
    let outcome = deliver::deliver(&h.app, &local).await;
    let Outcome::Sent(reply) = outcome else {
        panic!("expected Sent, got {outcome:?}")
    };
    deliver::record(&h.app, &local, Outcome::Sent(reply)).await;
    let fwd = h.app.db.claim_due_message().await.unwrap().unwrap();
    assert_eq!(fwd.kind, "forward");
    let fraw = String::from_utf8_lossy(&fwd.raw).to_string();
    assert!(fraw.contains("DKIM-Signature: v=1; a=rsa-sha256;"), "{fraw}");
    assert!(fraw.contains("d=sloth.test;"), "{fraw}");

    // ---- AUTH LOGIN by hand, the way some clients still do it ------------------
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", h.submission_port)).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut l = String::new();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("220"), "{l}");
    w.write_all(b"EHLO gmail.example\r\n").await.unwrap();
    let mut caps = Vec::new();
    loop {
        l.clear();
        r.read_line(&mut l).await.unwrap();
        caps.push(l.trim().to_string());
        if l.starts_with("250 ") {
            break;
        }
    }
    assert!(caps.iter().any(|c| c.ends_with("AUTH PLAIN LOGIN")), "{caps:?}");
    assert!(!caps.iter().any(|c| c.ends_with("STARTTLS")), "{caps:?}");
    for (send, want) in [
        ("AUTH LOGIN\r\n".to_string(), "334 VXNlcm5hbWU6"),
        (format!("{}\r\n", b64("paul@sloth.test")), "334 UGFzc3dvcmQ6"),
        (format!("{}\r\n", b64(PASSWORD)), "235 2.7.0"),
        ("AUTH PLAIN\r\n".to_string(), "503 5.5.1 already"),
        ("MAIL FROM:<paul@sloth.test>\r\n".to_string(), "250"),
        ("RCPT TO:<x@elsewhere.test>\r\n".to_string(), "250"),
        ("DATA\r\n".to_string(), "354"),
    ] {
        w.write_all(send.as_bytes()).await.unwrap();
        l.clear();
        r.read_line(&mut l).await.unwrap();
        assert!(l.starts_with(want), "sent {send:?}, wanted {want}, got {l}");
    }
    w.write_all(good).await.unwrap();
    w.write_all(b".\r\nQUIT\r\n").await.unwrap();
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("250 2.0.0 ok: queued as"), "{l}");
    let m = h.app.db.claim_due_message().await.unwrap().unwrap();
    assert_eq!(m.rcpt_to, "x@elsewhere.test");
    assert_eq!(m.kind, "send");
}

#[tokio::test]
async fn failed_logins_lock_the_ip_out() {
    let h = harness().await;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let bad = base64::engine::general_purpose::STANDARD.encode("\0paul@sloth.test\0wrong");
    let mut codes = Vec::new();
    for _ in 0..5 {
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", h.submission_port)).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut r = BufReader::new(r);
        let mut l = String::new();
        r.read_line(&mut l).await.unwrap();
        w.write_all(b"EHLO x\r\n").await.unwrap();
        loop {
            l.clear();
            r.read_line(&mut l).await.unwrap();
            if l.starts_with("250 ") {
                break;
            }
        }
        w.write_all(format!("AUTH PLAIN {bad}\r\n").as_bytes()).await.unwrap();
        l.clear();
        r.read_line(&mut l).await.unwrap();
        codes.push(l[..3].to_string());
    }
    assert_eq!(codes, ["535", "535", "535", "535", "421"]);
    // Locked out: the next connection gets no greeting at all.
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", h.submission_port)).await.unwrap();
    let mut r = BufReader::new(stream);
    let mut l = String::new();
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_line(&mut l))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((n, l.as_str()), (0, ""));
    // Port 25 is unaffected.
    smtp_submit(h.smtp_port, "a@b.test", "paul@sloth.test", b"Subject: x\r\n\r\nx\r\n")
        .await
        .unwrap();
}

/// Raw SMTP up to an accepted MAIL FROM, for tests that speak RCPT by hand.
async fn smtp_session_after_mail(
    port: u16,
) -> (
    tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut l = String::new();
    r.read_line(&mut l).await.unwrap();
    for cmd in ["HELO client.sloth.test\r\n", "MAIL FROM:<a@b.test>\r\n"] {
        w.write_all(cmd.as_bytes()).await.unwrap();
        l.clear();
        r.read_line(&mut l).await.unwrap();
        assert!(l.starts_with("250"), "{l}");
    }
    (r, w)
}

#[tokio::test]
async fn guessing_recipients_ends_the_connection() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let h = harness().await;
    let (mut r, mut w) = smtp_session_after_mail(h.smtp_port).await;
    let mut replies = Vec::new();
    let mut l = String::new();
    for i in 0..40 {
        // A wrong SRS hash, a mailbox that is not there, a domain that is not ours: all guesses.
        let rcpt = match i % 3 {
            0 => format!("SRS0=aaaaaaaaa{i}=AA=x.test=y@sloth.test"),
            1 => format!("nobody{i}@quiet.test"),
            _ => format!("x{i}@elsewhere.test"),
        };
        if w.write_all(format!("RCPT TO:<{rcpt}>\r\n").as_bytes()).await.is_err() {
            break;
        }
        l.clear();
        if r.read_line(&mut l).await.unwrap_or(0) == 0 {
            break;
        }
        replies.push(l[..3].to_string());
    }
    assert_eq!(replies.last().map(String::as_str), Some("421"), "{replies:?}");
    assert!(
        replies.len() <= 11,
        "the connection must end after a handful of bad recipients: {replies:?}"
    );
    // Why an SRS address was refused is nobody's business.
    let (mut r, mut w) = smtp_session_after_mail(h.smtp_port).await;
    w.write_all(b"RCPT TO:<SRS0=aaaaaaaaaa=AA=x.test=y@sloth.test>\r\n").await.unwrap();
    l.clear();
    r.read_line(&mut l).await.unwrap();
    assert_eq!(l.trim(), "550 5.1.1 no such user");
}

#[tokio::test]
async fn without_an_srs_secret_no_srs_address_exists() {
    crate::tls::install_crypto_provider();
    let dir = Dir::new("nosrs");
    // A host that only sends: nothing forwards, so the config needs no srs_secret.
    let cfg = Config::parse(&format!(
        r#"
hostname = "mail.sloth.test"
tls = false
data_dir = "{}"
[[site]]
name = "party"
domains = ["sendonly.test"]
[[domain]]
name = "sendonly.test"
"#,
        dir.path.display()
    ))
    .unwrap();
    let db = Db::open(&cfg.db_path()).await.unwrap();
    let dkim = DkimKeys::load(&cfg).unwrap();
    let app = App::new(cfg, db, dkim, MessageAuthenticator::new_system_conf().unwrap());
    let smtp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = smtp.local_addr().unwrap().port();
    tokio::spawn(smtpd::serve(app.clone(), None, smtp));

    // With no secret the key would be the empty string, which anyone can sign with.
    let forged = crate::srs::rewrite("", "victim@elsewhere.test", "sendonly.test");
    assert!(forged.starts_with("SRS0="), "{forged}");
    let err = smtp_submit(port, "", &forged, b"Subject: relayed\r\n\r\nspam\r\n")
        .await
        .unwrap_err();
    assert_eq!(rejection(err), (550, [5, 1, 1], "no such user".to_string()));
    assert!(app.db.claim_due_message().await.unwrap().is_none(), "nothing may be relayed");
}

#[tokio::test]
async fn one_message_is_one_received_event_per_site() {
    let h = harness().await;
    smtp_submit_as(
        h.smtp_port,
        None,
        "a@b.test",
        &["one@sloth.test", "two@sloth.test", "x@other.test"],
        b"From: a@b.test\r\nSubject: to three\r\n\r\nx\r\n",
    )
    .await
    .unwrap();
    let events = h.app.db.due_events(20).await.unwrap();
    let mut seen: Vec<(String, serde_json::Value)> = events
        .iter()
        .filter(|e| e.event_type == "mail.received")
        .map(|e| (e.site.clone(), serde_json::from_str::<serde_json::Value>(&e.body).unwrap()))
        .collect();
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(seen.len(), 2, "one event per site, not per recipient");
    let (site, ev) = &seen[0];
    assert_eq!(site, "other");
    assert_eq!(ev["data"]["to"], serde_json::json!(["x@other.test"]));
    assert_eq!(
        ev["data"]["envelope"]["rcpt_to"],
        serde_json::json!(["x@other.test"]),
        "another site's recipients stay private"
    );
    let (site, ev) = &seen[1];
    assert_eq!(site, "party");
    assert_eq!(ev["data"]["to"], serde_json::json!(["one@sloth.test", "two@sloth.test"]));
    assert_eq!(
        ev["data"]["envelope"]["rcpt_to"],
        serde_json::json!(["one@sloth.test", "two@sloth.test"])
    );
}

#[tokio::test]
async fn mail_is_not_acknowledged_when_it_cannot_be_stored() {
    let h = harness().await;
    h.app.db.execute_for_test("DROP TABLE inbound").await.unwrap();
    // Kept mail lives only in the inbound table: a 250 here would lose it.
    let err = smtp_submit(h.smtp_port, "a@b.test", "dmarc@quiet.test", b"Subject: report\r\n\r\nx\r\n")
        .await
        .unwrap_err();
    assert_eq!(rejection(err).0, 451);
    // And a forward is not queued for a message the sender will send again.
    let err = smtp_submit(h.smtp_port, "a@b.test", "someone@quiet.test", b"Subject: hello\r\n\r\nx\r\n")
        .await
        .unwrap_err();
    assert_eq!(rejection(err).0, 451);
    assert!(h.app.db.claim_due_message().await.unwrap().is_none());
}
