//! What a service hands out - an otpauth:// URI or a bare base32 secret - turned into
//! the arguments the device wants, plus the live self-test.

use std::num::NonZeroU8;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::device::{Algo, Device, Digits, Error, Kind, NAME_MAX, Params};

pub struct Resolved {
    pub name: String,
    pub secret: Zeroizing<Vec<u8>>,
    pub params: Params,
}

/// The parameters a URI may carry, before they are checked.
struct UriParams {
    digits: u8,
    period: u8,
    algo: Algo,
}

/// Accepts what QR codes hand out: unpadded, any case, with spaces.
pub fn decode_base32(s: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let clean: Zeroizing<String> = Zeroizing::new(
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| Error::Value("secret is not valid base32".into()))
}

/// `otpauth://totp/Issuer:account?secret=...&issuer=...&digits=6&period=30&algorithm=SHA1`
///
/// This is what a QR code decodes to. Anything other than TOTP is rejected: HOTP
/// counters would need state the device does not keep.
fn parse_otpauth(uri: &str) -> Result<(String, Zeroizing<Vec<u8>>, UriParams), Error> {
    let bad = |m: &str| Error::Value(format!("bad URI: {m}"));
    let u = url::Url::parse(uri).map_err(|_| bad("not an otpauth:// URI"))?;
    if u.scheme() != "otpauth" {
        return Err(bad("not an otpauth:// URI"));
    }
    let kind = u.host_str().unwrap_or("").to_ascii_lowercase();
    if kind != "totp" {
        return Err(bad(&format!("only TOTP is supported, not {kind}")));
    }
    let label = percent_encoding::percent_decode_str(u.path().trim_start_matches('/'))
        .decode_utf8_lossy()
        .into_owned();
    let mut secret = None;
    let mut issuer_param = None;
    let mut params = UriParams {
        digits: Params::DEFAULT.digits.wire(),
        period: Params::DEFAULT.period.get(),
        algo: Params::DEFAULT.algo,
    };
    for (k, v) in u.query_pairs() {
        match &*k {
            "secret" => secret = Some(Zeroizing::new(v.into_owned())),
            "issuer" => issuer_param = Some(v.into_owned()),
            "digits" => params.digits = v.parse().map_err(|_| bad("digits"))?,
            "period" => params.period = v.parse().map_err(|_| bad("period"))?,
            "algorithm" => {
                params.algo = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => Algo::Sha1,
                    "SHA256" => Algo::Sha256,
                    other => return Err(bad(&format!("unsupported algorithm {other}"))),
                };
            }
            _ => {}
        }
    }
    let secret = secret.ok_or_else(|| bad("URI has no secret"))?;
    // Label is "Issuer:account" or just "account"; the issuer parameter wins when both
    // are present, per the Google Authenticator convention.
    let (label_issuer, account) = match label.rsplit_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    let issuer = issuer_param.unwrap_or(label_issuer);
    let name = if issuer.is_empty() {
        account
    } else if account.is_empty() {
        issuer
    } else {
        format!("{issuer}:{account}")
    };
    let name: String = name.chars().take(NAME_MAX).collect();
    Ok((name, decode_base32(&secret)?, params))
}

/// Explicit values win over what the URI says. The device would refuse anything but
/// 6 or 8 digits and a non-zero period; better to say so here, in words.
pub fn resolve(
    source: &str,
    name: Option<&str>,
    digits: Option<u8>,
    period: Option<u8>,
    sha256: bool,
) -> Result<Resolved, Error> {
    let (name, secret, from_uri) = if source.starts_with("otpauth://") {
        let (uri_name, secret, p) = parse_otpauth(source)?;
        (name.map_or(uri_name, str::to_string), secret, Some(p))
    } else {
        let name = name.ok_or_else(|| Error::Value("a bare base32 secret needs a name".into()))?;
        (name.to_string(), decode_base32(source)?, None)
    };
    let digits = digits
        .or(from_uri.as_ref().map(|p| p.digits))
        .unwrap_or(Params::DEFAULT.digits.wire());
    let period = period
        .or(from_uri.as_ref().map(|p| p.period))
        .unwrap_or(Params::DEFAULT.period.get());
    let algo = if sha256 {
        Algo::Sha256
    } else {
        from_uri.as_ref().map_or(Params::DEFAULT.algo, |p| p.algo)
    };
    let params = Params {
        algo,
        digits: Digits::from_wire(digits)
            .ok_or_else(|| Error::Value("digits must be 6 or 8".into()))?,
        period: NonZeroU8::new(period)
            .ok_or_else(|| Error::Value("period must be at least 1 second".into()))?,
    };
    Ok(Resolved {
        name,
        secret,
        params,
    })
}

/// The RFC 6238 test seed ("12345678901234567890"): what the self-test and the
/// lifecycle check store, never a real credential.
pub const TEST_SECRET: &str = "JBSWY3DPEHPK3PXP";

/// Seconds the current code stays valid: the time left in its period.
#[must_use]
pub fn seconds_left(params: Params) -> u64 {
    let period = u64::from(params.period.get());
    period - crate::device::now() % period
}

/// HOTP reference implementation for the live comparison.
fn hotp_sha1(secret: &[u8], counter: u64, digits: Digits) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = usize::from(h[19] & 0x0F);
    let bin = u32::from_be_bytes([h[o] & 0x7F, h[o + 1], h[o + 2], h[o + 3]]);
    let width = digits.count();
    let modulus = 10u32.pow(u32::from(digits.wire()));
    format!("{:0width$}", bin % modulus)
}

/// One code from the device against an independent HMAC on the host, at the current
/// time: proves the whole path, not the arithmetic (the RFC 6238 vectors run against
/// the same core code in the firmware's host tests). Uses a name no real credential
/// would have and removes it afterwards; one tap, `button` says on what.
pub fn selftest(
    dev: &mut Device,
    button: &str,
    mut report: impl FnMut(&str),
) -> Result<bool, Error> {
    let name = "_selftest";
    let secret = decode_base32(TEST_SECRET)?;
    dev.add(name, &secret, Kind::Totp(Params::DEFAULT), true)?;
    report(&format!("  press {button} when the light turns amber"));
    let now = crate::device::now();
    let got = dev.code(name, Some(now));
    dev.delete(name)?;
    let got = got?;
    let reference = hotp_sha1(&secret, now / 30, Digits::Six);
    let pass = got == reference;
    report(&format!(
        "  {}  device {got}  independent HMAC {reference}",
        if pass { "PASS" } else { "FAIL" }
    ));
    Ok(pass)
}
