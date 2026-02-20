use evidenceos_core::pln::PlnProfile;
use std::fs;
use std::path::Path;

pub fn load_pln_profile(data_dir: &Path) -> Result<Option<PlnProfile>, String> {
    let path = data_dir.join("pln_profile.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|_| "failed to read pln_profile.json".to_string())?;
    let profile: PlnProfile = serde_json::from_slice(&bytes)
        .map_err(|_| "failed to decode pln_profile.json".to_string())?;
    profile
        .validate()
        .map_err(|e| format!("invalid pln_profile.json: {e}"))?;
    Ok(Some(profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_and_validate_profile() {
        let dir = tempfile::tempdir().expect("tmp");
        let payload = r#"{
            "cpu_model":"x",
            "syscall_cycles":{"mean_cycles":1,"p95_cycles":2,"p99_cycles":3},
            "wasm_instruction_cycles":{"mean_cycles":1,"p95_cycles":2,"p99_cycles":3},
            "recommended_pln_constant_cost":{"syscall_constant_cost":3,"wasm_instruction_constant_cost":3}
        }"#;
        fs::write(dir.path().join("pln_profile.json"), payload).expect("write");
        let out = load_pln_profile(dir.path()).expect("load");
        assert!(out.is_some());
    }

    #[test]
    fn invalid_profile_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        let payload = r#"{
            "cpu_model":"",
            "syscall_cycles":{"mean_cycles":1,"p95_cycles":2,"p99_cycles":3},
            "wasm_instruction_cycles":{"mean_cycles":1,"p95_cycles":2,"p99_cycles":3},
            "recommended_pln_constant_cost":{"syscall_constant_cost":3,"wasm_instruction_constant_cost":3}
        }"#;
        fs::write(dir.path().join("pln_profile.json"), payload).expect("write");
        assert!(load_pln_profile(dir.path()).is_err());
    }
}
