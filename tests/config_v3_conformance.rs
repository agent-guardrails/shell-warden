//! Full v3 policy vectors are shared with the normative schema validator.
use shell_warden::checker::config::load_str;

#[test]
fn v3_config_schema_vectors_match_the_strict_loader() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/config_v3");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert!(fixtures.len() >= 20);
    for fixture in fixtures {
        let name = fixture["path"].as_str().unwrap();
        let text = std::fs::read_to_string(root.join(name)).unwrap();
        assert_eq!(
            load_str(&text).is_ok(),
            fixture["valid"].as_bool().unwrap(),
            "{name}"
        );
    }
}
