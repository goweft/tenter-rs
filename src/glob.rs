use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::path::Path;

pub fn build_globset(patterns: &[&str]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        match GlobBuilder::new(p)
            .case_insensitive(true)
            .literal_separator(false)
            .build()
        {
            Ok(g) => { builder.add(g); }
            Err(e) => eprintln!("tenter: invalid glob pattern {:?}: {}", p, e),
        }
    }
    builder.build().unwrap_or_else(|_| GlobSet::empty())
}

pub fn build_globset_owned(patterns: &[String]) -> GlobSet {
    let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    build_globset(&refs)
}

pub fn glob_matches(gs: &GlobSet, rel_path: &str) -> bool {
    let normalised = rel_path.replace('\\', "/");
    if gs.is_match(&normalised) {
        return true;
    }
    if let Some(base) = Path::new(&normalised).file_name() {
        if gs.is_match(base) {
            return true;
        }
    }
    false
}

pub fn single_glob_matches(pattern: &str, rel_path: &str) -> bool {
    match GlobBuilder::new(pattern)
        .case_insensitive(true)
        .literal_separator(false)
        .build()
    {
        Ok(g) => {
            let normalised = rel_path.replace('\\', "/");
            let matcher = g.compile_matcher();
            if matcher.is_match(&normalised) {
                return true;
            }
            if let Some(base) = Path::new(&normalised).file_name() {
                if matcher.is_match(base) {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}
