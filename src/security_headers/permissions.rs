use super::{Error as SecurityHeaderError, Result};
use ext_php_rs::php_const;
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_enum, php_impl};
use std::collections::BTreeMap;
use std::fmt::Write;
use strum_macros::Display;

/// Supported Permissions-Policy features.
///
/// Each variant corresponds to a feature name in the Permissions-Policy header
/// (kebab-case). See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
#[php_enum]
#[php(name = "Hardened\\SecurityHeaders\\PermissionsPolicyFeature")]
#[derive(Display, Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
#[strum(serialize_all = "kebab-case")]
pub enum Feature {
    /// Controls whether the current document is allowed to gather information
    /// about the acceleration of the device through the Accelerometer interface.
    #[php(value = "accelerometer")]
    Accelerometer,

    /// Controls whether the current document is allowed to gather information
    /// about the amount of light in the environment around the device through
    /// the AmbientLightSensor interface.
    #[php(value = "ambient-light-sensor")]
    AmbientLightSensor,

    /// Controls whether the current document is allowed to use the
    /// Attribution Reporting API.
    #[php(value = "attribution-reporting")]
    AttributionReporting,

    /// Controls whether the current document is allowed to autoplay media
    /// requested through the HTMLMediaElement interface. When disabled without
    /// user gesture, play() will reject with NotAllowedError.
    #[php(value = "autoplay")]
    Autoplay,

    /// Controls whether the use of the Web Bluetooth API is allowed.
    /// When disabled, Bluetooth methods will either return false or reject.
    #[php(value = "bluetooth")]
    Bluetooth,

    /// Controls access to the Topics API. Disallowed calls to browsingTopics()
    /// or Sec-Browsing-Topics header will fail with NotAllowedError.
    #[php(value = "browsing-topics")]
    BrowsingTopics,

    /// Controls whether the current document is allowed to use video input devices.
    /// When disabled, getUserMedia() will reject with NotAllowedError.
    #[php(value = "camera")]
    Camera,

    /// Controls access to the Compute Pressure API.
    #[php(value = "compute-pressure")]
    ComputePressure,

    /// Controls whether the current document can be treated as cross-origin isolated.
    #[php(value = "cross-origin-isolated")]
    CrossOriginIsolated,

    /// Controls the allocation of the top-level origin's fetchLater() quota.
    #[php(value = "deferred-fetch")]
    DeferredFetch,

    /// Controls the allocation of the shared cross-origin subframe fetchLater() quota.
    #[php(value = "deferred-fetch-minimal")]
    DeferredFetchMinimal,

    /// Controls whether the current document may capture display media via getDisplayMedia().
    /// When disabled, getDisplayMedia() will reject with NotAllowedError.
    #[php(value = "display-capture")]
    DisplayCapture,

    /// Controls whether the current document is allowed to use the Encrypted Media
    /// Extensions API (EME). When disabled, requestMediaKeySystemAccess() will reject.
    #[php(value = "encrypted-media")]
    EncryptedMedia,

    /// Controls whether the current document is allowed to use Element.requestFullscreen().
    /// When disabled, requestFullscreen() will reject with TypeError.
    #[php(value = "fullscreen")]
    Fullscreen,

    /// Controls whether the current document is allowed to use the Gamepad API.
    /// When disabled, getGamepads() will throw SecurityError and events won't fire.
    #[php(value = "gamepad")]
    Gamepad,

    /// Controls whether the current document is allowed to use the Geolocation Interface.
    /// When disabled, geolocation callbacks will error with PERMISSION_DENIED.
    #[php(value = "geolocation")]
    Geolocation,

    /// Controls whether the current document is allowed to gather information
    /// about device orientation through the Gyroscope interface.
    #[php(value = "gyroscope")]
    Gyroscope,

    /// Controls whether the current document is allowed to use the WebHID API.
    /// Allows communication with HID devices like gamepads or keyboards.
    #[php(value = "hid")]
    Hid,

    /// Controls whether the document may use the Federated Credential Management API
    /// (FedCM) via navigator.credentials.get({identity:…}).
    #[php(value = "identity-credentials-get")]
    IdentityCredentialsGet,

    /// Controls whether the document may use the Idle Detection API to detect user idle/active state.
    #[php(value = "idle-detection")]
    IdleDetection,

    /// Controls access to the language detection functionality of Translator & Language Detector APIs.
    #[php(value = "language-detector")]
    LanguageDetector,

    /// Controls whether the document may gather data on locally-installed fonts via queryLocalFonts().
    #[php(value = "local-fonts")]
    LocalFonts,

    /// Controls whether the document may gather device orientation via the Magnetometer interface.
    #[php(value = "magnetometer")]
    Magnetometer,

    /// Controls whether the document is allowed to use audio input devices.
    /// When disabled, getUserMedia() will reject with NotAllowedError.
    #[php(value = "microphone")]
    Microphone,

    /// Controls whether the document may use the Web MIDI API.
    /// When disabled, requestMIDIAccess() will reject with SecurityError.
    #[php(value = "midi")]
    Midi,

    /// Controls whether the document may use the WebOTP API to retrieve one-time passwords.
    #[php(value = "otp-credentials")]
    OtpCredentials,

    /// Controls whether the document may use the Payment Request API.
    /// When disabled, PaymentRequest() will throw SecurityError.
    #[php(value = "payment")]
    Payment,

    /// Controls whether the document may enter Picture-in-Picture mode via the API.
    #[php(value = "picture-in-picture")]
    PictureInPicture,

    /// Controls whether the document may use Web Authentication API to create new credentials.
    #[php(value = "publickey-credentials-create")]
    PublickeyCredentialsCreate,

    /// Controls whether the document may use Web Authentication API to retrieve stored credentials.
    #[php(value = "publickey-credentials-get")]
    PublickeyCredentialsGet,

    /// Controls whether the document may use the Screen Wake Lock API to keep the screen on.
    #[php(value = "screen-wake-lock")]
    ScreenWakeLock,

    /// Controls whether the document may use the Web Serial API to communicate with serial devices.
    #[php(value = "serial")]
    Serial,

    /// Controls whether the document may list and select speakers via the Output Devices API.
    #[php(value = "speaker-selection")]
    SpeakerSelection,

    /// Controls whether an embedded document may use the Storage Access API for third-party cookies.
    #[php(value = "storage-access")]
    StorageAccess,

    /// Controls access to the translation functionality of Translator & Language Detector APIs.
    #[php(value = "translator")]
    Translator,

    /// Controls access to the Summarizer API.
    #[php(value = "summarizer")]
    Summarizer,

    /// Controls whether the document may use the WebUSB API to connect to USB devices.
    #[php(value = "usb")]
    Usb,

    /// Controls whether the document may use the Web Share API (navigator.share()).
    #[php(value = "web-share")]
    WebShare,

    /// Controls whether the document may use the Window Management API to manage windows.
    #[php(value = "window-management")]
    WindowManagement,

    /// Controls whether the document may use the WebXR Device API to interact with XR sessions.
    #[php(value = "xr-spatial-tracking")]
    XrSpatialTracking,
}

/// Permissions-Policy header builder.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\PermissionsPolicy")]
pub struct PermissionsPolicy {
    policies: BTreeMap<Feature, Vec<String>>,
}

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
    fn allow(&mut self, feature: Feature, origins: Vec<String>) {
        self.policies.insert(feature, origins);
    }

    /// Deny a feature entirely (empty allowlist).
    ///
    /// # Parameters
    /// - `feature`: one of the defined `Feature` tokens.
    ///
    /// # Errors
    /// - if `feature` is not recognized.
    fn deny(&mut self, feature: Feature) {
        self.policies.insert(feature, Vec::new());
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
        Function::try_from_function("header")
            .ok_or(SecurityHeaderError::HeaderUnavailable)?
            .try_call(vec![&format!("Permissions-Policy: {}", self.build())])
            .map_err(|e| SecurityHeaderError::HeaderCallFailed(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Feature, PermissionsPolicy};
    use crate::run_php_example;

    #[test]
    fn build_empty_policy_returns_empty() {
        let pp = PermissionsPolicy::__construct();
        assert_eq!(pp.build(), "");
    }

    #[test]
    fn build_star_allowlist() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow(Feature::Geolocation, vec!["*".into()]);
        assert_eq!(pp.build(), "geolocation=(*)");
    }

    #[test]
    fn build_empty_for_deny() {
        let mut pp = PermissionsPolicy::__construct();
        pp.deny(Feature::Camera);
        assert_eq!(pp.build(), "camera=()");
    }

    #[test]
    fn build_self_and_host() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow(
            Feature::StorageAccess,
            vec!["self".into(), "https://api.example.com".into()],
        );
        assert_eq!(
            pp.build(),
            "storage-access=(self \"https://api.example.com\")"
        );
    }

    #[test]
    fn build_src_token() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow(Feature::LanguageDetector, vec!["src".into()]);
        assert_eq!(pp.build(), "language-detector=('src')");
    }

    #[test]
    fn build_multiple_features_in_order() {
        let mut pp = PermissionsPolicy::__construct();
        pp.allow(Feature::StorageAccess, vec!["*".into()]);
        pp.deny(Feature::Translator);
        pp.allow(
            Feature::Midi,
            vec!["self".into(), "src".into(), "https://a.example.com".into()],
        );
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
