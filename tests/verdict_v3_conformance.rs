//! The shared v3 vectors exercise the same closed model and semantic validator
//! used by the producer. There is no second response-version implementation.
use shell_warden::checker::verdict::{MAX_VERDICT_BYTES, VerdictEnvelope};

#[test]
fn canonical_v3_vectors_match_the_active_validator() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/verdict_v3");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert!(fixtures.len() >= 50);
    for fixture in fixtures {
        let name = fixture["path"].as_str().unwrap();
        let bytes = std::fs::read(root.join(name)).unwrap();
        let accepted = if bytes.len() > MAX_VERDICT_BYTES {
            false
        } else {
            serde_json::from_slice::<VerdictEnvelope>(&bytes)
                .map_err(|e| e.to_string())
                .and_then(|envelope| {
                    envelope.validate_against(
                        fixture["expectedInvocationId"].as_str().unwrap(),
                        fixture["positionalIndexes"].as_array().unwrap().len(),
                    )?;
                    envelope.to_wire().map(|_| ())
                })
                .is_ok()
        };
        assert_eq!(accepted, fixture["valid"].as_bool().unwrap(), "{name}");
    }
}
