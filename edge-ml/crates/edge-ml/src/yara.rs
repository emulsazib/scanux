//! YARA-X rule matching (feature "yara").

pub struct Rules(yara_x::Rules);

impl Rules {
    pub fn compile(sources: &[(&str, &str)]) -> Result<Self, String> {
        let mut c = yara_x::Compiler::new();
        for (origin, src) in sources {
            c.add_source(yara_x::SourceCode::from(*src).with_origin(*origin))
                .map_err(|e| e.to_string())?;
        }
        Ok(Self(c.build()))
    }

    pub fn load_dir(dir: &std::path::Path) -> Result<Self, String> {
        let mut files = vec![];
        for e in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let p = e.map_err(|e| e.to_string())?.path();
            if p.extension().is_some_and(|x| x == "yar" || x == "yara") {
                files.push((p.display().to_string(), std::fs::read_to_string(&p).map_err(|e| e.to_string())?));
            }
        }
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        Self::compile(&refs)
    }

    /// Matching rule identifiers; scan errors yield no matches (fail open, logged by caller).
    pub fn scan(&self, data: &[u8]) -> Vec<String> {
        let mut s = yara_x::Scanner::new(&self.0);
        s.set_timeout(std::time::Duration::from_millis(500));
        match s.scan(data) {
            Ok(r) => r.matching_rules().map(|m| m.identifier().to_string()).collect(),
            Err(_) => vec![],
        }
    }
}
