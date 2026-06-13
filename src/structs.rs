//! `.bxs` struct definitions: C-like syntax, applied at the cursor to emit
//! one annotation per field.
//!
//! ```text
//! struct boot_hdr {
//!     str magic[8];
//!     u32le kernel_size;
//!     raw reserved[16];   // fixed-size types take no length
//! }
//! ```

use std::collections::HashMap;

use crate::annotations::{Region, RegionType};

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub rtype: RegionType,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
}

impl StructDef {
    pub fn total_size(&self) -> u64 {
        self.fields.iter().map(|f| f.size).sum()
    }

    /// Annotations for this struct laid down at `base`.
    pub fn apply(&self, base: u64) -> Vec<Region> {
        let mut out = Vec::new();
        let mut off = base;
        for f in &self.fields {
            out.push(Region {
                start: off,
                end: off + f.size,
                label: format!("{}.{}", self.name, f.name),
                rtype: f.rtype,
            });
            off += f.size;
        }
        out
    }
}

/// Parse a .bxs document. Returns all structs keyed by name.
pub fn parse(text: &str) -> Result<HashMap<String, StructDef>, String> {
    let mut structs = HashMap::new();
    // Strip // comments, then tokenize on whitespace and punctuation.
    let mut cleaned = String::new();
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("");
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in cleaned.chars() {
        match ch {
            '{' | '}' | ';' | '[' | ']' => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                tokens.push(ch.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }

    let mut it = tokens.into_iter().peekable();
    while let Some(tok) = it.next() {
        if tok != "struct" {
            return Err(format!("expected 'struct', found '{tok}'"));
        }
        let name = it.next().ok_or("expected struct name")?;
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(format!("bad struct name '{name}'"));
        }
        if it.next().as_deref() != Some("{") {
            return Err(format!("expected '{{' after struct {name}"));
        }
        let mut fields = Vec::new();
        loop {
            let t = it
                .next()
                .ok_or_else(|| format!("unterminated struct {name}"))?;
            if t == "}" {
                break;
            }
            let rtype = RegionType::parse(&t)
                .ok_or_else(|| format!("unknown type '{t}' in struct {name}"))?;
            let fname = it
                .next()
                .filter(|f| f.chars().all(|c| c.is_alphanumeric() || c == '_') && !f.is_empty())
                .ok_or_else(|| format!("expected field name after '{t}' in {name}"))?;
            let mut size = rtype.fixed_size();
            if it.peek().map(String::as_str) == Some("[") {
                it.next();
                let len_tok = it.next().ok_or("expected array length")?;
                let len = parse_len(&len_tok)
                    .ok_or_else(|| format!("bad length '{len_tok}' for {name}.{fname}"))?;
                if it.next().as_deref() != Some("]") {
                    return Err(format!("expected ']' after length for {name}.{fname}"));
                }
                match rtype.fixed_size() {
                    // arrays of fixed-size ints become one raw-sized region per
                    // field; keep it simple: scale the size, keep the type
                    Some(s) => size = Some(s * len),
                    None => size = Some(len),
                }
            }
            let size = size
                .ok_or_else(|| format!("type '{t}' needs an explicit [len] for {name}.{fname}"))?;
            if rtype == RegionType::Float && !(size == 4 || size == 8) {
                return Err(format!("float field {name}.{fname} must be [4] or [8]"));
            }
            if it.next().as_deref() != Some(";") {
                return Err(format!("expected ';' after field {name}.{fname}"));
            }
            fields.push(Field {
                name: fname,
                rtype,
                size,
            });
        }
        if fields.is_empty() {
            return Err(format!("struct {name} has no fields"));
        }
        structs.insert(name.clone(), StructDef { name, fields });
    }
    if structs.is_empty() {
        return Err("no structs found".into());
    }
    Ok(structs)
}

fn parse_len(tok: &str) -> Option<u64> {
    if let Some(hex) = tok.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        tok.parse().ok()
    }
    .filter(|&n| n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_struct() {
        let src = r#"
            // android-ish header
            struct boot_hdr {
                str magic[8];
                u32le kernel_size;
                u32le kernel_addr;
                raw reserved[0x10];
                float ratio[4];
            }
        "#;
        let m = parse(src).unwrap();
        let s = &m["boot_hdr"];
        assert_eq!(s.fields.len(), 5);
        assert_eq!(s.total_size(), 8 + 4 + 4 + 16 + 4);
        let regions = s.apply(0x100);
        assert_eq!(regions[0].label, "boot_hdr.magic");
        assert_eq!((regions[0].start, regions[0].end), (0x100, 0x108));
        assert_eq!((regions[1].start, regions[1].end), (0x108, 0x10C));
        assert_eq!(regions[4].rtype, RegionType::Float);
    }

    #[test]
    fn multiple_structs_and_arrays() {
        let src = "struct a { u8 x; u16le pair[2]; } struct b { u64be big; }";
        let m = parse(src).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m["a"].total_size(), 1 + 4); // u16le[2] = 4 bytes
        assert_eq!(m["b"].total_size(), 8);
    }

    #[test]
    fn errors() {
        assert!(parse("struct x { }").is_err()); // empty
        assert!(parse("struct x { u99 f; }").is_err()); // bad type
        assert!(parse("struct x { str s; }").is_err()); // str needs len
        assert!(parse("struct x { u8 f }").is_err()); // missing ;
        assert!(parse("blah").is_err());
    }
}
