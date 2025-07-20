use ext_php_rs::builders::ModuleBuilder;
#[cfg(feature = "file_sanitizers")]
pub mod file;
#[cfg(feature = "html_sanitizer")]
pub mod html;

pub(crate) fn build(mut module: ModuleBuilder) -> ModuleBuilder {
    #[cfg(feature = "html_sanitizer")]
    {
        module = module.class::<html::HtmlSanitizer>();
    }
    #[cfg(feature = "file_sanitizers")]
    {
        module = module.class::<file::png::PngSanitizer>();
        module = module.class::<file::archive::ArchiveSanitizer>();
    }
    module
}
