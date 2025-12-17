use super::{Error as SecurityHeaderError, Result};
use ext_php_rs::php_const;
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use php_hardened_macro::php_enum_constants;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// Supported Permissions-Policy features.
///
/// Each variant corresponds to a feature name in the Permissions-Policy header
/// (kebab-case). See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum Feature {
    /// Controls whether the current document is allowed to gather information
    /// about the acceleration of the device through the Accelerometer interface.
    Accelerometer,

    /// Controls whether the current document is allowed to gather information
    /// about the amount of light in the environment around the device through
    /// the AmbientLightSensor interface.
    AmbientLightSensor,

    /// Controls whether the current document is allowed to use the
    /// Attribution Reporting API.
    AttributionReporting,

    /// Controls whether the current document is allowed to autoplay media
    /// requested through the HTMLMediaElement interface. When disabled without
    /// user gesture, play() will reject with NotAllowedError.
    Autoplay,

    /// Controls whether the use of the Web Bluetooth API is allowed.
    /// When disabled, Bluetooth methods will either return false or reject.
    Bluetooth,

    /// Controls access to the Topics API. Disallowed calls to browsingTopics()
    /// or Sec-Browsing-Topics header will fail with NotAllowedError.
    BrowsingTopics,

    /// Controls whether the current document is allowed to use video input devices.
    /// When disabled, getUserMedia() will reject with NotAllowedError.
    Camera,

    /// Controls access to the Compute Pressure API.
    ComputePressure,

    /// Controls whether the current document can be treated as cross-origin isolated.
    CrossOriginIsolated,

    /// Controls the allocation of the top-level origin’s fetchLater() quota.
    DeferredFetch,

    /// Controls the allocation of the shared cross-origin subframe fetchLater() quota.
    DeferredFetchMinimal,

    /// Controls whether the current document may capture display media via getDisplayMedia().
    /// When disabled, getDisplayMedia() will reject with NotAllowedError.
    DisplayCapture,

    /// Controls whether the current document is allowed to use the Encrypted Media
    /// Extensions API (EME). When disabled, requestMediaKeySystemAccess() will reject.
    EncryptedMedia,

    /// Controls whether the current document is allowed to use Element.requestFullscreen().
    /// When disabled, requestFullscreen() will reject with TypeError.
    Fullscreen,

    /// Controls whether the current document is allowed to use the Gamepad API.
    /// When disabled, getGamepads() will throw SecurityError and events won’t fire.
    Gamepad,

    /// Controls whether the current document is allowed to use the Geolocation Interface.
    /// When disabled, geolocation callbacks will error with PERMISSION_DENIED.
    Geolocation,

    /// Controls whether the current document is allowed to gather information
    /// about device orientation through the Gyroscope interface.
    Gyroscope,

    /// Controls whether the current document is allowed to use the WebHID API.
    /// Allows communication with HID devices like gamepads or keyboards.
    Hid,

    /// Controls whether the document may use the Federated Credential Management API
    /// (FedCM) via navigator.credentials.get({identity:…}).
    IdentityCredentialsGet,

    /// Controls whether the document may use the Idle Detection API to detect user idle/active state.
    IdleDetection,

    /// Controls access to the language detection functionality of Translator & Language Detector APIs.
    LanguageDetector,

    /// Controls whether the document may gather data on locally-installed fonts via queryLocalFonts().
    LocalFonts,

    /// Controls whether the document may gather device orientation via the Magnetometer interface.
    Magnetometer,

    /// Controls whether the document is allowed to use audio input devices.
    /// When disabled, getUserMedia() will reject with NotAllowedError.
    Microphone,

    /// Controls whether the document may use the Web MIDI API.
    /// When disabled, requestMIDIAccess() will reject with SecurityError.
    Midi,

    /// Controls whether the document may use the WebOTP API to retrieve one-time passwords.
    OtpCredentials,

    /// Controls whether the document may use the Payment Request API.
    /// When disabled, PaymentRequest() will throw SecurityError.
    Payment,

    /// Controls whether the document may enter Picture-in-Picture mode via the API.
    PictureInPicture,

    /// Controls whether the document may use Web Authentication API to create new credentials.
    PublickeyCredentialsCreate,

    /// Controls whether the document may use Web Authentication API to retrieve stored credentials.
    PublickeyCredentialsGet,

    /// Controls whether the document may use the Screen Wake Lock API to keep the screen on.
    ScreenWakeLock,

    /// Controls whether the document may use the Web Serial API to communicate with serial devices.
    Serial,

    /// Controls whether the document may list and select speakers via the Output Devices API.
    SpeakerSelection,

    /// Controls whether an embedded document may use the Storage Access API for third-party cookies.
    StorageAccess,

    /// Controls access to the translation functionality of Translator & Language Detector APIs.
    Translator,

    /// Controls access to the Summarizer API.
    Summarizer,

    /// Controls whether the document may use the WebUSB API to connect to USB devices.
    Usb,

    /// Controls whether the document may use the Web Share API (navigator.share()).
    WebShare,

    /// Controls whether the document may use the Window Management API to manage windows.
    WindowManagement,

    /// Controls whether the document may use the WebXR Device API to interact with XR sessions.
    XrSpatialTracking,
}

/// Permissions-Policy header builder.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\PermissionsPolicy")]
pub struct PermissionsPolicy {
    policies: BTreeMap<Feature, Vec<String>>,
}

#[php_enum_constants(Feature, "src/security_headers/permissions.rs")]
#[php_impl]
impl PermissionsPolicy {
    #[php_const]
    const ORIGIN_SELF: &str = "self";
    #[php_const]
    const ORIGIN_ANY: &str = "*";
    #[php_const]
    const ORIGIN_SRC: &str = "src";
    /// Constructs a new Permissions-Policy builder with no features allowed.
    ///
    /// # Returns
    /// - `PermissionsPolicy` New instance with an empty feature map.
    fn __construct() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }
    /// Allow a feature for the given list of origins.
    ///
    /// # Parameters
    /// - `feature`: one of the defined `Feature` tokens.
    /// - `origins`: list of allowlist entries, e.g. `"self"`, `"*"`, `"src"`, or quoted origins.
    ///
    /// # Errors
    /// - if `feature` is not recognized.
    fn allow(&mut self, feature: &str, origins: Vec<String>) -> Result<()> {
        let feat =
            Feature::from_str(feature).map_err(|_| SecurityHeaderError::InvalidFeature(feature.to_string()))?;
        self.policies.insert(feat, origins);
        Ok(())
    }

    /// Deny a feature entirely (empty allowlist).
    ///
    /// # Parameters
    /// - `feature`: one of the defined `Feature` tokens.
    ///
    /// # Errors
    /// - if `feature` is not recognized.
    fn deny(&mut self, feature: &str) -> Result<()> {
        let feat =
            Feature::from_str(feature).map_err(|_| SecurityHeaderError::InvalidFeature(feature.to_string()))?;
        self.policies.insert(feat, Vec::new());
        Ok(())
    }

    /// Builds the Permissions-Policy header value.
    ///
    /// # Returns
    /// - `String`, e.g.:
    ///   `geolocation=(self "https://api.example.com"), camera=()`
    fn build(&self) -> String {
        let mut header = String::new();
        let mut first = true;

        for (feat, origins) in &self.policies {
            if !first {
                header.push_str(", ");
            }
            first = false;

            write!(header, "{feat}=(").unwrap();

            if !origins.is_empty() {
                let mut first_origin = true;
                for origin in origins {
                    if !first_origin {
                        header.push(' ');
                    }
                    first_origin = false;

                    match origin.as_str() {
                        "*" => header.push('*'),
                        "self" => header.push_str("self"),
                        "src" => header.push_str("'src'"),
                        other => write!(header, "\"{other}\"").unwrap(),
                    }
                }
            }

            header.push(')');
        }

        header
    }

    /// Sends the Permissions-Policy header via PHP `header()` function.
    ///
    /// # Errors
    /// - Returns an error if PHP `header()` cannot be invoked.
    fn send(&self) -> Result<()> {
        #[cfg(not(test))]
        {
            Function::try_from_function("header")
                .ok_or(SecurityHeaderError::HeaderUnavailable)?
                .try_call(vec![&format!("Permissions-Policy: {}", self.build())])
                .map_err(|e| SecurityHeaderError::HeaderCallFailed(e.to_string()))?;
            Ok(())
        }
        #[cfg(test)]
        panic!("send() can not be called from tests");
    }
}

#[cfg(test)]
mod tests {
    use super::PermissionsPolicy;
    use crate::run_php_example;

    #[test]
    fn build_empty_policy_returns_empty() {
        let pp = PermissionsPolicy::__construct();
        assert_eq!(pp.build(), "");
    }

    #[test]
    fn build_star_allowlist() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow("geolocation", vec!["*".into()]).unwrap();
        assert_eq!(pp.build(), "geolocation=(*)");
    }

    #[test]
    fn build_empty_for_deny() {
        let mut pp = PermissionsPolicy::__construct();
        pp.deny("camera").unwrap();
        assert_eq!(pp.build(), "camera=()");
    }

    #[test]
    fn build_self_and_host() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow(
            "storage-access",
            vec!["self".into(), "https://api.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            pp.build(),
            "storage-access=(self \"https://api.example.com\")"
        );
    }

    #[test]
    fn build_src_token() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow("language-detector", vec!["src".into()]).unwrap();
        assert_eq!(pp.build(), "language-detector=('src')");
    }

    #[test]
    fn build_multiple_features_in_order() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow("storage-access", vec!["*".into()]).unwrap();
        pp.deny("translator").unwrap();
        pp.allow(
            "midi",
            vec!["self".into(), "src".into(), "https://a.example.com".into()],
        )
        .unwrap();
        assert_eq!(
            pp.build(),
            "midi=(self 'src' \"https://a.example.com\"), storage-access=(*), translator=()"
        );
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("security-headers/permissions-policy")?;
        Ok(())
    }
}
