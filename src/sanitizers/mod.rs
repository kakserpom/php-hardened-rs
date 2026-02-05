use ext_php_rs::builders::ModuleBuilder;
#[cfg(feature = "file_sanitizers")]
pub mod file;
#[cfg(feature = "html_sanitizer")]
pub mod html;
#[cfg(feature = "svg_sanitizer")]
pub mod svg;

pub(crate) fn build(mut module: ModuleBuilder) -> ModuleBuilder {
    #[cfg(feature = "html_sanitizer")]
    {
        module = module.class::<html::HtmlSanitizer>();
        module = module.enumeration::<html::Flag>();
    }
    #[cfg(feature = "file_sanitizers")]
    {
        module = module.class::<file::png::PngSanitizer>();
        module = module.class::<file::archive::ArchiveSanitizer>();
    }
    #[cfg(feature = "svg_sanitizer")]
    {
        module = module.class::<svg::SvgSanitizer>();
    }
    module
}
