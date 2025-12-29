use std::collections::HashSet;

/// Elements that are ALWAYS blocked regardless of configuration
pub const BLOCKED_ELEMENTS: &[&str] = &[
    "script",          // JavaScript execution
    "foreignObject",   // Can embed arbitrary HTML
    "set",             // SMIL animation
    "animate",         // SMIL animation
    "animateMotion",   // SMIL animation
    "animateTransform", // SMIL animation
    "animateColor",    // SMIL animation (deprecated but dangerous)
    "handler",         // Event handler element
    "listener",        // Listener element
];

/// Minimal safe elements (strict preset)
pub const SAFE_ELEMENTS_STRICT: &[&str] = &[
    "svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text",
    "tspan",
];

/// Standard safe elements (default preset)
pub const SAFE_ELEMENTS_STANDARD: &[&str] = &[
    // Container elements
    "svg",
    "g",
    "defs",
    "symbol",
    "marker",
    "clipPath",
    "mask",
    "pattern",
    // Shape elements
    "path",
    "rect",
    "circle",
    "ellipse",
    "line",
    "polyline",
    "polygon",
    // Text elements
    "text",
    "tspan",
    "textPath",
    // Gradient elements
    "linearGradient",
    "radialGradient",
    "stop",
    // Filter elements
    "filter",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feComposite",
    "feConvolveMatrix",
    "feDiffuseLighting",
    "feDisplacementMap",
    "feDistantLight",
    "feDropShadow",
    "feFlood",
    "feFuncA",
    "feFuncB",
    "feFuncG",
    "feFuncR",
    "feGaussianBlur",
    "feImage",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "fePointLight",
    "feSpecularLighting",
    "feSpotLight",
    "feTile",
    "feTurbulence",
    // Other safe elements
    "title",
    "desc",
    "metadata",
    "image",
    "use",
    "switch",
];

/// Permissive elements (includes links and fonts)
pub const SAFE_ELEMENTS_PERMISSIVE: &[&str] = &[
    // All standard elements
    "svg",
    "g",
    "defs",
    "symbol",
    "marker",
    "clipPath",
    "mask",
    "pattern",
    "path",
    "rect",
    "circle",
    "ellipse",
    "line",
    "polyline",
    "polygon",
    "text",
    "tspan",
    "textPath",
    "linearGradient",
    "radialGradient",
    "stop",
    "filter",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feComposite",
    "feConvolveMatrix",
    "feDiffuseLighting",
    "feDisplacementMap",
    "feDistantLight",
    "feDropShadow",
    "feFlood",
    "feFuncA",
    "feFuncB",
    "feFuncG",
    "feFuncR",
    "feGaussianBlur",
    "feImage",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "fePointLight",
    "feSpecularLighting",
    "feSpotLight",
    "feTile",
    "feTurbulence",
    "title",
    "desc",
    "metadata",
    "image",
    "use",
    "switch",
    // Additional permissive elements
    "a",
    "view",
    "font",
    "font-face",
    "font-face-src",
    "font-face-uri",
    "font-face-format",
    "font-face-name",
    "glyph",
    "missing-glyph",
    "hkern",
    "vkern",
];

/// Standard safe attributes
pub const SAFE_ATTRIBUTES: &[&str] = &[
    // Core attributes
    "id",
    "class",
    "lang",
    "tabindex",
    "role",
    "aria-label",
    "aria-labelledby",
    "aria-describedby",
    "aria-hidden",
    // Positioning
    "x",
    "y",
    "x1",
    "y1",
    "x2",
    "y2",
    "cx",
    "cy",
    "r",
    "rx",
    "ry",
    "width",
    "height",
    "viewBox",
    "preserveAspectRatio",
    "transform",
    "transform-origin",
    // Path data
    "d",
    "points",
    "pathLength",
    // Visual attributes
    "fill",
    "fill-opacity",
    "fill-rule",
    "stroke",
    "stroke-width",
    "stroke-opacity",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-dasharray",
    "stroke-dashoffset",
    "stroke-miterlimit",
    "opacity",
    "visibility",
    "display",
    "color",
    "color-interpolation",
    "color-interpolation-filters",
    // Text attributes
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "font-variant",
    "font-stretch",
    "text-anchor",
    "dominant-baseline",
    "alignment-baseline",
    "baseline-shift",
    "letter-spacing",
    "word-spacing",
    "text-decoration",
    "writing-mode",
    "glyph-orientation-horizontal",
    "glyph-orientation-vertical",
    "direction",
    "unicode-bidi",
    "dx",
    "dy",
    "rotate",
    "textLength",
    "lengthAdjust",
    "startOffset",
    "method",
    "spacing",
    // Gradient/Pattern attributes
    "gradientUnits",
    "gradientTransform",
    "spreadMethod",
    "offset",
    "stop-color",
    "stop-opacity",
    "patternUnits",
    "patternContentUnits",
    "patternTransform",
    // Filter attributes
    "filterUnits",
    "primitiveUnits",
    "result",
    "in",
    "in2",
    "stdDeviation",
    "mode",
    "type",
    "values",
    "k1",
    "k2",
    "k3",
    "k4",
    "operator",
    "radius",
    "baseFrequency",
    "numOctaves",
    "seed",
    "stitchTiles",
    "surfaceScale",
    "diffuseConstant",
    "specularConstant",
    "specularExponent",
    "kernelUnitLength",
    "order",
    "kernelMatrix",
    "divisor",
    "bias",
    "targetX",
    "targetY",
    "edgeMode",
    "preserveAlpha",
    "azimuth",
    "elevation",
    "pointsAtX",
    "pointsAtY",
    "pointsAtZ",
    "limitingConeAngle",
    "scale",
    "xChannelSelector",
    "yChannelSelector",
    "flood-color",
    "flood-opacity",
    "lighting-color",
    // Clip/Mask attributes
    "clipPathUnits",
    "clip-path",
    "clip-rule",
    "maskUnits",
    "maskContentUnits",
    "mask",
    // Marker attributes
    "markerWidth",
    "markerHeight",
    "markerUnits",
    "orient",
    "refX",
    "refY",
    "marker-start",
    "marker-mid",
    "marker-end",
    // Symbol/Use attributes
    "overflow",
    // Links (requires URL sanitization)
    "href",
    "xlink:href",
    // Image attributes
    "crossorigin",
    // NOTE: 'style' attribute is NOT included by default because Ammonia
    // doesn't sanitize CSS content. CSS expressions, external URLs, and
    // other dangerous content can be injected via style attributes.
    // Users can explicitly add it via add_allowed_attributes() at their own risk.
    // SVG namespace
    "xmlns",
    "xmlns:xlink",
    "version",
    "baseProfile",
];

/// Safe CSS properties for style attributes
pub const SAFE_CSS_PROPERTIES: &[&str] = &[
    // Colors
    "color",
    "fill",
    "stroke",
    "stop-color",
    "flood-color",
    "lighting-color",
    // Opacity
    "opacity",
    "fill-opacity",
    "stroke-opacity",
    "stop-opacity",
    "flood-opacity",
    // Stroke
    "stroke-width",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-dasharray",
    "stroke-dashoffset",
    "stroke-miterlimit",
    // Fill
    "fill-rule",
    // Text
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "font-variant",
    "font-stretch",
    "text-anchor",
    "text-decoration",
    "letter-spacing",
    "word-spacing",
    "dominant-baseline",
    "alignment-baseline",
    "baseline-shift",
    "writing-mode",
    "direction",
    // Layout
    "display",
    "visibility",
    "overflow",
    // Transform
    "transform",
    "transform-origin",
    // Filter
    "filter",
    // Clip
    "clip-path",
    "clip-rule",
    // Mask
    "mask",
    // Marker
    "marker",
    "marker-start",
    "marker-mid",
    "marker-end",
    // Miscellaneous
    "isolation",
    "mix-blend-mode",
    "paint-order",
    "vector-effect",
    "image-rendering",
    "shape-rendering",
    "text-rendering",
    "color-interpolation",
    "color-interpolation-filters",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Strict,
    Standard,
    Permissive,
}

impl Preset {
    pub fn elements(&self) -> HashSet<String> {
        match self {
            Preset::Strict => SAFE_ELEMENTS_STRICT.iter().map(|s| s.to_string()).collect(),
            Preset::Standard => SAFE_ELEMENTS_STANDARD.iter().map(|s| s.to_string()).collect(),
            Preset::Permissive => SAFE_ELEMENTS_PERMISSIVE.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn attributes(&self) -> HashSet<String> {
        // All presets use the same attribute set
        SAFE_ATTRIBUTES.iter().map(|s| s.to_string()).collect()
    }

    pub fn css_properties(&self) -> HashSet<String> {
        SAFE_CSS_PROPERTIES.iter().map(|s| s.to_string()).collect()
    }
}

impl TryFrom<&str> for Preset {
    type Error = ();

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "strict" => Ok(Preset::Strict),
            "standard" => Ok(Preset::Standard),
            "permissive" => Ok(Preset::Permissive),
            _ => Err(()),
        }
    }
}

/// Check if an element is in the blocked list
pub fn is_blocked_element(element: &str) -> bool {
    BLOCKED_ELEMENTS.contains(&element)
}

/// Check if an attribute is an event handler (on*)
pub fn is_event_handler_attribute(attr: &str) -> bool {
    attr.to_lowercase().starts_with("on")
}
