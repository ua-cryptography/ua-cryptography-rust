use std::collections::{BTreeMap, BTreeSet};

use crate::errors::UsageError;

/// What starts an option.
const OPTION_PREFIX: &str = "--";
/// What separates an option from its value in one argument.
const VALUE_SEPARATOR: char = '=';

/// The parsed options of one command: `--name value`, `--name=value` and flags. Only the options the command declares
/// are accepted; repeatable options collect every value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    values: BTreeMap<String, Vec<String>>,
    flags: BTreeSet<String>,
}

impl Arguments {
    /// Parses `arguments` against the command's `options` (taking a value) and `flags`.
    pub fn parse(arguments: &[String], options: &[&str], flags: &[&str]) -> Result<Self, UsageError> {
        let mut parsed = Self {
            values: BTreeMap::new(),
            flags: BTreeSet::new(),
        };
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            let Some(option) = argument.strip_prefix(OPTION_PREFIX) else {
                return Err(UsageError::UnexpectedArgument {
                    argument: argument.clone(),
                });
            };
            let (name, inline_value) = match option.split_once(VALUE_SEPARATOR) {
                Some((name, value)) => (name, Some(value)),
                None => (option, None),
            };
            if flags.contains(&name) {
                if inline_value.is_some() {
                    return Err(UsageError::FlagWithValue { name: name.to_owned() });
                }
                parsed.flags.insert(name.to_owned());
            } else if options.contains(&name) {
                let value = match inline_value {
                    Some(value) => value.to_owned(),
                    None => {
                        index += 1;
                        take_value(arguments, index, name)?
                    }
                };
                parsed.values.entry(name.to_owned()).or_default().push(value);
            } else {
                return Err(UsageError::UnknownOption { name: name.to_owned() });
            }
            index += 1;
        }
        Ok(parsed)
    }

    /// True when the flag is given.
    pub fn has_flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    /// The value of a single-valued option, if given; refuses one given twice.
    pub fn find(&self, name: &str) -> Result<Option<&str>, UsageError> {
        match self.values.get(name).map(Vec::as_slice) {
            None => Ok(None),
            Some([value]) => Ok(Some(value.as_str())),
            Some(_) => Err(UsageError::RepeatedOption { name: name.to_owned() }),
        }
    }

    /// The value of a required single-valued option.
    pub fn get(&self, name: &str) -> Result<&str, UsageError> {
        self.find(name)?
            .ok_or_else(|| UsageError::MissingOption { name: name.to_owned() })
    }

    /// Every value of a repeatable option, in the order given.
    pub fn select(&self, name: &str) -> &[String] {
        match self.values.get(name) {
            Some(values) => values,
            None => &[],
        }
    }

    /// A positive number option, or `default` when it is not given.
    pub fn get_positive_number(&self, name: &str, default: u32) -> Result<u32, UsageError> {
        let Some(text) = self.find(name)? else {
            return Ok(default);
        };
        match text.parse::<i32>() {
            Ok(number) if number > 0 => Ok(number.unsigned_abs()),
            _ => Err(UsageError::NotPositiveNumber { name: name.to_owned() }),
        }
    }
}

// The value after an option: present and not itself an option.
fn take_value(arguments: &[String], index: usize, name: &str) -> Result<String, UsageError> {
    match arguments.get(index) {
        Some(value) if !value.starts_with(OPTION_PREFIX) => Ok(value.clone()),
        _ => Err(UsageError::MissingValue { name: name.to_owned() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(arguments: &[&str]) -> Vec<String> {
        arguments.iter().map(|argument| (*argument).to_owned()).collect()
    }

    #[test]
    fn values_come_after_the_option_or_after_an_equals_sign() {
        let parsed = Arguments::parse(&strings(&["--in", "a", "--in=b", "--force"]), &["in"], &["force"]).unwrap();
        assert_eq!(parsed.select("in"), ["a", "b"]);
        assert!(parsed.has_flag("force"));
        assert_eq!(
            parsed.find("in"),
            Err(UsageError::RepeatedOption { name: "in".to_owned() })
        );
    }

    #[test]
    fn an_option_followed_by_another_option_has_no_value() {
        assert_eq!(
            Arguments::parse(&strings(&["--in", "--force"]), &["in"], &["force"]),
            Err(UsageError::MissingValue { name: "in".to_owned() })
        );
    }

    #[test]
    fn flags_take_no_value_and_unknown_options_are_refused() {
        assert_eq!(
            Arguments::parse(&strings(&["--force=yes"]), &[], &["force"]),
            Err(UsageError::FlagWithValue {
                name: "force".to_owned()
            })
        );
        assert_eq!(
            Arguments::parse(&strings(&["--what"]), &[], &[]),
            Err(UsageError::UnknownOption {
                name: "what".to_owned()
            })
        );
        assert_eq!(
            Arguments::parse(&strings(&["file"]), &[], &[]),
            Err(UsageError::UnexpectedArgument {
                argument: "file".to_owned()
            })
        );
    }

    #[test]
    fn numbers_must_be_positive() {
        let parsed = Arguments::parse(&strings(&["--days", "0"]), &["days", "curve"], &[]).unwrap();
        assert_eq!(parsed.get_positive_number("curve", 257), Ok(257));
        assert_eq!(
            parsed.get_positive_number("days", 365),
            Err(UsageError::NotPositiveNumber {
                name: "days".to_owned()
            })
        );
    }
}
