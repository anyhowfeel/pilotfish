//! Settings categories (rail entries).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Category {
    #[default]
    Appearance,
    Capture,
    Display,
    Names,
    Locations,
    Performance,
    Shortcuts,
    About,
}

impl Category {
    pub const ALL: [Category; 8] = [
        Category::Appearance,
        Category::Capture,
        Category::Display,
        Category::Names,
        Category::Locations,
        Category::Performance,
        Category::Shortcuts,
        Category::About,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Appearance => "Appearance",
            Category::Capture => "Capture",
            Category::Display => "Display",
            Category::Names => "Names",
            Category::Locations => "Locations",
            Category::Performance => "Performance",
            Category::Shortcuts => "Shortcuts",
            Category::About => "About",
        }
    }

    pub fn parse(s: &str) -> Option<Category> {
        Category::ALL
            .into_iter()
            .find(|c| c.label().eq_ignore_ascii_case(s.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips() {
        for c in Category::ALL {
            assert_eq!(Category::parse(c.label()), Some(c));
        }
        assert_eq!(Category::parse("x"), None);
    }
}
