use anyhow::{anyhow, bail};
use ext_php_rs::binary::Binary;
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use rand::distr::{Alphabetic, Alphanumeric, SampleString, Uniform};
use rand::{Rng as _, rng, seq::IndexedRandom};
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

    /// Randomly selects one element from the given list.
    ///
    /// # Parameters
    /// - `choices`: PHP array of values to pick from.
    ///
    /// # Returns
    /// - `mixed|null`: A randomly chosen element, or `null` if `choices` is empty.
    fn choose(choices: Vec<&Zval>) -> Option<Zval> {
        let mut rng = rand::rng();
        choices
            .choose(&mut rng)
            .map(|choice| choice.shallow_clone())
    }

    /// Randomly selects exactly `amount` distinct elements without replacement.
    ///
    /// # Parameters
    /// - `amount`: Number of elements to select.
    /// - `choices`: PHP array of values to pick from.
    ///
    /// # Returns
    /// - `mixed[]`: Array of selected values.
    ///
    /// # Exceptions
    /// - Throws `Exception` if `amount` is greater than the number of available choices.
    fn choose_multiple(amount: usize, choices: Vec<&Zval>) -> Vec<Zval> {
        let mut rng = rand::rng();
        choices
            .choose_multiple(&mut rng, amount)
            .map(|choice| choice.shallow_clone())
            .collect()
    }

    /// Randomly selects one element from weighted choices.
    ///
    /// # Parameters
    /// - `choices`: PHP array of `[value, weight]` pairs, where `weight` is an integer.
    ///
    /// # Returns
    /// - `array{0: mixed, 1: int}` Two‐element array: the chosen value and its weight.
    ///
    /// # Exceptions
    /// - Throws `Exception` if any entry is not a two‐element array or weight is not an integer.
    /// - Throws `Exception` if selection fails.
    fn choose_weighted(choices: Vec<Vec<&Zval>>) -> anyhow::Result<Vec<Zval>> {
        let mut rng = rand::rng();
        let len = choices.len();
        let vec = choices.iter().try_fold(
            Vec::with_capacity(len),
            |mut vec, choice| -> anyhow::Result<_> {
                if choice.len() != 2 {
                    bail!("every choice must be an array of two elements — value and weight");
                }
                let value = choice[0];
                let weight = choice[1]
                    .long()
                    .ok_or_else(|| anyhow!("second element must be integer"))?;
                vec.push((value, weight));
                Ok(vec)
            },
        )?;
        let choice = vec.choose_weighted(&mut rng, |pair| pair.1)?;
        Ok(vec![
            choice.0.shallow_clone(),
            Zval::try_from(choice.1).map_err(|err| anyhow!("{err:?}"))?,
        ])
    }

    /// Randomly selects `amount` elements from weighted choices without replacement.
    ///
    /// # Parameters
    /// - `amount`: Number of elements to select.
    /// - `choices`: PHP array of `[value, weight]` pairs, where `weight` is a float.
    ///
    /// # Returns
    /// - `mixed[]`: Array of selected values.
    ///
    /// # Exceptions
    /// - Throws `Exception` if any entry is not a two‐element array or weight is not a float.
    /// - Throws `Exception` if selection fails.
    fn choose_multiple_weighted(
        amount: usize,
        choices: Vec<Vec<&Zval>>,
    ) -> anyhow::Result<Vec<Zval>> {
        let mut rng = rand::rng();
        let len = choices.len();
        let vec = choices.iter().try_fold(
            Vec::with_capacity(len),
            |mut vec, choice| -> anyhow::Result<_> {
                if choice.len() != 2 {
                    bail!("every choice must be an array of two elements — value and weight");
                }
                let value = choice[0];
                let weight = choice[1]
                    .double()
                    .ok_or_else(|| anyhow!("second element must be float"))?;
                vec.push((value, weight));
                Ok(vec)
            },
        )?;
        Ok(vec
            .choose_multiple_weighted(&mut rng, amount, |pair| pair.1)?
            .map(|pair| pair.0.shallow_clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;
    use crate::run_php_example;
    use unicode_segmentation::UnicodeSegmentation;

    #[test]
    fn test_alphanumeric() {
        let s = Rng::alphanumeric(10);
        assert_eq!(s.len(), 10);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_alphabetic() {
        let s = Rng::alphabetic(8);
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_ints() {
        let v = Rng::ints(5, 0, 10).unwrap();
        assert_eq!(v.len(), 5);
        for &i in &v {
            assert!((0..=10).contains(&i));
        }
    }

    #[test]
    fn test_int_valid_and_invalid() {
        let i = Rng::int(1, 3).unwrap();
        assert!((1..=3).contains(&i));
        assert!(Rng::int(5, 0).is_err(), "should error when low > high");
    }

    #[test]
    fn test_custom_unicode_chars() {
        let pool = "абв";
        let s = Rng::custom_unicode_chars(5, pool);
        assert_eq!(s.chars().count(), 5);
        assert!(s.chars().all(|c| pool.contains(c)));
        let empty = Rng::custom_unicode_chars(5, "");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_custom_unicode_graphemes() {
        let pool = "🙈🙉🙊";
        let s = Rng::custom_unicode_graphemes(4, pool).unwrap();
        // Each grapheme is one of the pool
        let graphemes: Vec<&str> = pool.graphemes(true).collect();
        for g in s.graphemes(true) {
            assert!(graphemes.contains(&g));
        }
        let empty = Rng::custom_unicode_graphemes(3, "").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_custom_ascii() {
        let pool = "ABC";
        let s = Rng::custom_ascii(6, pool);
        assert_eq!(s.len(), 6);
        assert!(s.chars().all(|c| pool.contains(c)));
        let empty = Rng::custom_ascii(4, "");
        assert!(empty.is_empty());
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("rng")?;
        Ok(())
    }
}
