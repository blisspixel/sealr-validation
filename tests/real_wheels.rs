//! Portable public-API checks complement the authenticated Linux installation.

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::SystemTime};

struct PrivateInput(PathBuf);

impl Drop for PrivateInput {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn released_project_wheels_evaluate_after_source_deletion() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("artifacts.json")).unwrap()).unwrap();
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let private = PrivateInput(std::env::temp_dir().join(format!(
        "sealr-downstream-test-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir(&private.0).unwrap();
    for artifact in manifest["artifacts"].as_array().unwrap() {
        let filename = artifact["filename"].as_str().unwrap();
        let content = fs::read(root.join("artifacts").join(filename))
            .expect("run python scripts/acquire.py first");
        let digest: String = Sha256::digest(&content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest, artifact["sha256"]);
        assert_eq!(content.len() as u64, artifact["bytes"].as_u64().unwrap());
        let path = private.0.join(filename);
        fs::write(&path, content).unwrap();
        let outcome = apply_with_options(
            Request {
                source: Source::Path(&path),
                policy: &Policy::default_v1(),
                dest: None,
            },
            &ApplyOptions::new()
                .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1),
        );
        assert!(
            !outcome.rejected(),
            "{filename}: {:?}",
            outcome.view.findings
        );
        let archive = outcome.into_verified_archive().unwrap();
        assert_eq!(
            archive.members().len() as u64,
            artifact["expected"]["members"].as_u64().unwrap()
        );
        fs::remove_file(&path).unwrap();
        match evaluate_wheel(filename, &archive, WheelLimits::default()) {
            WheelEvaluation::Admitted {
                plan, identities, ..
            } => {
                assert_eq!(identities.source_sha256, digest);
                assert_eq!(
                    identities.artifact_sha256,
                    artifact["expected"]["artifact_sha256"]
                );
                assert_eq!(
                    plan.entries().len() as u64,
                    artifact["expected"]["plan_entries"].as_u64().unwrap()
                );
                for member in archive.members() {
                    archive
                        .read_member(&member.canonical_path, member.actual_uncomp_size.unwrap())
                        .unwrap();
                }
                println!(
                    "{filename}: {} members, {} plan entries, artifact {}",
                    archive.members().len(),
                    plan.entries().len(),
                    identities.artifact_sha256
                );
            }
            other => panic!("{filename}: {other:?}"),
        }
        assert!(!path.exists());
    }
}
