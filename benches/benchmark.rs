use criterion::{Criterion, criterion_group, criterion_main};
use php_hardened::sanitizers::html::{Flag, HtmlSanitizer};
use std::hint::black_box;

fn bench_htmlsanitizer(c: &mut Criterion) {
    fn payload(target_size: usize) -> String {
        let mut buf = String::from(
            r#"<!DOCTYPE html><html lang="ru"><head><meta charset="UTF - 8"><title>Benchmark HTML Purifier</title></head><body>"#,
        );
        while buf.len() < target_size {
            buf.push_str(r#"<div class="benchmark-item">Lorem ipsum dolor sit amet, <a href="javascript:alert(document.cookie)">consectetur</a> adipiscing elit. Quisque at.</div>"#);
        }
        buf.push_str(r#"</body></html>"#);
        buf
    }

    let payload10kb = payload(10 * 1024);
    let mut html_sanitizer = HtmlSanitizer::default();
    c.bench_function("html_sanitizer_10kb", |b| {
        b.iter(|| {
            let _ = black_box(html_sanitizer.clean(payload10kb.clone()).unwrap());
        })
    });

    c.bench_function("html_sanitizer_truncate_10k_to_5kb_in_ascii_mode", |b| {
        b.iter(|| {
            let _ = black_box(
                html_sanitizer
                    ._clean_and_truncate(payload10kb.clone(), 5 * 1024, &[Flag::Ascii], None)
                    .unwrap(),
            );
        })
    });
}

criterion_group!(benches, bench_htmlsanitizer);
criterion_main!(benches);
