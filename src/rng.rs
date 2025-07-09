use anyhow::bail;
use ext_php_rs::binary::Binary;
use ext_php_rs::{php_class, php_impl};
use rand::distr::{Alphabetic, Alphanumeric, SampleString, Uniform};
use rand::{Rng as _, rng};
use unicode_segmentation::UnicodeSegmentation;

#[php_class]
#[php(name = "Hardened\\Rng")]
pub struct Rng {}

#[php_impl]
impl Rng {
    /// Generate a random ASCII alphanumeric string of the specified length.
    ///
    /// # Parameters
    /// - `len`: Number of characters to generate.
    ///
    /// # Returns
    /// - `String` containing random ASCII alphanumeric characters.
    fn alphanumeric(len: usize) -> String {
        Alphanumeric.sample_string(&mut rng(), len)
    }

    /// Generate a random ASCII alphabetic string of the specified length.
    ///
    /// # Parameters
    /// - `len`: Number of characters to generate.
    ///
    /// # Returns
    /// - `String` containing random ASCII alphabetic characters.
    fn alphabetic(len: usize) -> String {
        Alphabetic.sample_string(&mut rng(), len)
    }

    /// Generate a sequence of random bytes of the specified length.
    ///
    /// # Parameters
    /// - `len`: Number of bytes to generate.
    ///
    /// # Returns
    /// - `Ok(Binary<u8>)` containing `len` random bytes.
    ///
    /// # Errors
    /// - Returns `Err` if the uniform distribution for `u8` cannot be created.
    fn bytes(len: usize) -> anyhow::Result<Binary<u8>> {
        Ok(Binary::from(
            rng()
                .sample_iter(Uniform::new_inclusive(u8::MIN, u8::MAX)?)
                .take(len)
                .collect::<Vec<_>>(),
        ))
    }

    /// Generate a vector of random integers in the inclusive range `[low, high]`.
    ///
    /// # Parameters
    /// - `len`: Number of integers to generate.
    /// - `low`: Lower bound (inclusive).
    /// - `high`: Upper bound (inclusive).
    ///
    /// # Returns
    /// - `Ok(Vec<i64>)` of length `len`.
    ///
    /// # Errors
    /// - Returns `Err` if the range is invalid (e.g. `low > high`) or distribution creation fails.
    fn ints(len: usize, low: i64, high: i64) -> anyhow::Result<Vec<i64>> {
        Ok(rng()
            .sample_iter(Uniform::new_inclusive(low, high)?)
            .take(len)
            .collect::<Vec<_>>())
    }

    /// Generate a single random integer in the inclusive range `[low, high]`.
    ///
    /// # Parameters
    /// - `low`: Lower bound (inclusive).
    /// - `high`: Upper bound (inclusive).
    ///
    /// # Returns
    /// - `Ok(i64)` random value.
    ///
    /// # Errors
    /// - Returns `Err` if `low > high` or if distribution creation fails.
    fn int(low: i64, high: i64) -> anyhow::Result<i64> {
        if low > high {
            bail!("low must not be greater than high")
        }
        Ok(rng().sample(Uniform::new_inclusive(low, high)?))
    }

    /// Sample random Unicode characters (code points) from the given string.
    ///
    /// # Parameters
    /// - `len`: Number of characters to generate.
    /// - `chars`: A string whose `char` elements form the sampling pool.
    ///
    /// # Returns
    /// - `String` of length `len`, or an empty string if `chars` is empty.
    fn custom_unicode_chars(len: usize, chars: &str) -> String {
        if chars.is_empty() {
            return String::new();
        }
        let unicode_chars = chars.chars().collect::<Vec<_>>();
        rng()
            .sample_iter(Uniform::new_inclusive(0, unicode_chars.len() - 1).unwrap())
            .take(len)
            .map(|n| unicode_chars[n])
            .collect()
    }

    /// Sample random Unicode grapheme clusters from the given string.
    ///
    /// # Parameters
    /// - `len`: Number of graphemes to generate.
    /// - `chars`: A string whose grapheme clusters form the sampling pool.
    ///
    /// # Returns
    /// - `Ok(String)` of concatenated grapheme clusters, or an empty string if none are found.
    ///
    /// # Errors
    /// - Returns `Err` if the grapheme index distribution cannot be created.
    fn custom_unicode_graphemes(len: usize, chars: &str) -> anyhow::Result<String> {
        let graphemes = chars.graphemes(true).collect::<Vec<&str>>();
        if graphemes.is_empty() {
            return Ok(String::new());
        }
        Ok(rng()
            .sample_iter(Uniform::new_inclusive(0, graphemes.len() - 1)?)
            .take(len)
            .map(|n| graphemes[n])
            .collect())
    }

    /// Sample random ASCII characters from the specified character set.
    ///
    /// # Parameters
    /// - `len`: Number of characters to generate.
    /// - `chars`: A string slice whose bytes form the sampling pool.
    ///
    /// # Returns
    /// - `String` of length `len`, or an empty string if `chars` is empty.
    fn custom_ascii(len: usize, chars: &str) -> String {
        let chars = chars.as_bytes();
        if chars.is_empty() {
            return String::new();
        }
        let range = Uniform::new_inclusive(0, chars.len() - 1).unwrap();
        rng()
            .sample_iter(range)
            .take(len)
            .map(|n| chars[n] as char)
            .collect()
    }
}
