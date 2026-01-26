use alloc::string::String;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpHeader {
    name: String,
    value: String,
}

impl HttpHeader {
    pub fn new(name: String, value: String) -> Self {
        Self { name, value }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn name_eq_ignore_case(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}
