//! edgeml: offline tooling for the edge model.
//!   edgeml build-bloom <hashes.txt> <out.bloom> [fp_rate]
//!   edgeml features <file>...           JSON lines, used for training parity tests
//!   edgeml scan [--bloom f] [--model linear.json] <file>...
//!   edgeml synth <benign|packed> <out>   synthetic PE for parity tests

use edge_ml::{extract, Bloom, EdgeEngine, LinearScorer, FEATURE_NAMES};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("build-bloom") if args.len() >= 3 => {
            let text = std::fs::read_to_string(&args[1])?;
            let fp = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(0.0001);
            let b = Bloom::from_hex_lines(&text, fp);
            b.write_to(&mut std::fs::File::create(&args[2])?)?;
            eprintln!("wrote {}", args[2]);
        }
        Some("features") => {
            for f in &args[1..] {
                let data = std::fs::read(f)?;
                let feats = extract(&data).map(|x| {
                    FEATURE_NAMES.iter().zip(x.values).map(|(n, v)| (n.to_string(), serde_json::json!(v))).collect::<serde_json::Map<_, _>>()
                });
                println!("{}", serde_json::json!({ "file": f, "order": FEATURE_NAMES, "features": feats }));
            }
        }
        Some("scan") => {
            let mut bloom = None;
            let mut scorer = LinearScorer::baseline();
            let mut files = vec![];
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--bloom" => bloom = Some(Bloom::read_from(&mut std::fs::File::open(it.next().ok_or("--bloom path")?)?)?),
                    "--model" => scorer = LinearScorer::from_json(&std::fs::read_to_string(it.next().ok_or("--model path")?)?)?,
                    f => files.push(f.to_string()),
                }
            }
            let engine = EdgeEngine::new(bloom, Box::new(scorer));
            for f in files {
                let v = engine.analyze_file(Path::new(&f))?;
                println!("{}", serde_json::json!({ "file": f, "verdict": v }));
            }
        }
        Some("synth") if args.len() >= 3 => {
            let shape = match args[1].as_str() {
                "benign" => edge_ml::testpe::Shape::Benign,
                _ => edge_ml::testpe::Shape::PackedRwx,
            };
            std::fs::write(&args[2], edge_ml::testpe::tiny_pe64(shape))?;
        }
        _ => {
            eprintln!("usage: edgeml build-bloom <hashes.txt> <out.bloom> [fp] | features <file>... | scan [--bloom f] [--model m.json] <file>...");
            std::process::exit(2);
        }
    }
    Ok(())
}
