//! Instrumented consumer experiment, separate from the unchanged copied handoff.
#![allow(clippy::result_large_err)]

#[allow(dead_code)]
mod stage;

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{
    apply_supervised, apply_with_options, ApplyOptions, LinuxWorker, MemberKind, Policy, Request,
    RetentionPlan, Source, ZipInterpretationProfile,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MEMBER_CAP: u64 = 256 * 1024;
const TOTAL_CAP: u64 = 1024 * 1024;
const PATH_CAP: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MemberPin {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfig {
    wheel: PathBuf,
    source_sha256: String,
    inventory_sha256: String,
    strategy: String,
    paths: Vec<MemberPin>,
    worker_manifest: PathBuf,
    verifier: PathBuf,
    installer_root: PathBuf,
    output_root: PathBuf,
}

fn options() -> ApplyOptions {
    ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1)
}

fn inventory(archive: &sealr::VerifiedArchive) -> Result<Vec<MemberPin>> {
    let mut members = archive
        .members()
        .iter()
        .filter(|member| !matches!(member.kind, MemberKind::Directory))
        .map(|member| {
            Ok(MemberPin {
                path: member.canonical_path.clone(),
                size: member.actual_uncomp_size.ok_or("member size is absent")?,
                sha256: member
                    .content_sha256
                    .clone()
                    .ok_or("member hash is absent")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    members.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(members)
}

fn inventory_digest(members: &[MemberPin]) -> Result<String> {
    Ok(stage::hex_sha256(&serde_json::to_vec(members)?))
}

fn generate_pins(root: &Path) -> Result<Value> {
    let artifacts: Value = serde_json::from_slice(&fs::read(root.join("artifacts.json"))?)?;
    let mut pins = Vec::new();
    for artifact in artifacts["artifacts"]
        .as_array()
        .ok_or("artifact list absent")?
    {
        let filename = artifact["filename"].as_str().ok_or("filename absent")?;
        let bytes = fs::read(root.join("artifacts").join(filename))?;
        if artifact["sha256"] != stage::hex_sha256(&bytes)
            || artifact["bytes"] != bytes.len() as u64
        {
            return Err(format!("pinned wheel changed: {filename}").into());
        }
        let policy = Policy::default_v1();
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: None,
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options(),
        );
        let archive = outcome
            .verified_archive()
            .ok_or("inventory admission failed")?;
        let members = inventory(archive)?;
        let semantic = members
            .iter()
            .filter(|member| {
                member.path.rsplit_once('/').is_some_and(|(root, leaf)| {
                    root.ends_with(".dist-info")
                        && !root.contains('/')
                        && matches!(leaf, "METADATA" | "WHEEL" | "RECORD" | "entry_points.txt")
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for required in ["METADATA", "WHEEL", "RECORD"] {
            if semantic
                .iter()
                .filter(|member| member.path.ends_with(&format!("/{required}")))
                .count()
                != 1
            {
                return Err(format!("inventory lacks unique semantic member {required}").into());
            }
        }
        let mut selected: BTreeMap<_, _> = semantic
            .iter()
            .map(|member| (member.path.clone(), member.clone()))
            .collect();
        let mut total = semantic.iter().map(|member| member.size).sum::<u64>();
        if total > TOTAL_CAP || semantic.iter().any(|member| member.size > MEMBER_CAP) {
            return Err("semantic working set exceeds experiment ceilings".into());
        }
        for member in &members {
            if selected.len() == PATH_CAP {
                break;
            }
            if !selected.contains_key(&member.path)
                && member.size <= MEMBER_CAP
                && total + member.size <= TOTAL_CAP
            {
                selected.insert(member.path.clone(), member.clone());
                total += member.size;
            }
        }
        pins.push(json!({
            "project": artifact["project"], "filename": filename,
            "source_sha256": artifact["sha256"], "inventory_sha256": inventory_digest(&members)?,
            "regular_members": members.len(), "semantic": semantic,
            "bounded": selected.into_values().collect::<Vec<_>>()
        }));
    }
    Ok(
        json!({"schema": "sealr.retention-path-pins.v1", "max_paths": PATH_CAP,
        "max_member_bytes": MEMBER_CAP, "max_total_bytes": TOTAL_CAP, "artifacts": pins}),
    )
}

fn require_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("expected regular non-link file: {}", path.display()).into());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn consume(config: RunConfig) -> Result<Value> {
    if !cfg!(target_os = "linux") {
        return Err("supervised experiment requires Linux".into());
    }
    if !matches!(
        config.strategy.as_str(),
        "baseline" | "semantic" | "bounded"
    ) {
        return Err("unknown retention strategy".into());
    }
    if config.paths.len() > PATH_CAP || (config.strategy == "baseline" && !config.paths.is_empty())
    {
        return Err("invalid requested retention path count".into());
    }
    let mut requested = BTreeSet::new();
    let mut requested_bytes = 0_u64;
    let mut retention = RetentionPlan::new(MEMBER_CAP, TOTAL_CAP);
    for member in &config.paths {
        requested_bytes = requested_bytes
            .checked_add(member.size)
            .ok_or("retention total overflow")?;
        if member.size > MEMBER_CAP
            || requested_bytes > TOTAL_CAP
            || !requested.insert(&member.path)
        {
            return Err("retention pin exceeds bounds or repeats a path".into());
        }
        retention.add_path(&member.path)?;
    }
    require_regular(&config.wheel)?;
    require_regular(&config.verifier)?;
    if fs::symlink_metadata(&config.output_root).is_ok() {
        return Err("installation output root must be absent".into());
    }
    let filename = config
        .wheel
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("wheel filename is not UTF-8")?
        .to_owned();
    if stage::hex_sha256(&fs::read(&config.wheel)?) != config.source_sha256 {
        return Err("wheel does not match its pinned source digest".into());
    }
    let worker = LinuxWorker::load_from_manifest(&config.worker_manifest)?;
    let policy = Policy::default_v1();
    let options = if config.strategy == "baseline" {
        options()
    } else {
        options().with_retention(retention)
    };
    let started = Instant::now();
    let outcome = apply_supervised(
        Request {
            source: Source::Path(&config.wheel),
            policy: &policy,
            dest: None,
        },
        &options,
        &worker,
    )?;
    let admission_seconds = started.elapsed().as_secs_f64();
    if outcome.rejected() {
        return Err(format!("admission failed: {:?}", outcome.view.findings).into());
    }
    let started = Instant::now();
    let canonical = outcome
        .canonical_evidence()
        .map_err(|finding| finding.detail)?;
    let private = stage::PrivateRoot::create()?;
    let view_path = private.path().join("view.json");
    let receipt_path = private.path().join("receipt.json");
    write_new(&view_path, &canonical.view_bytes)?;
    write_new(&receipt_path, &canonical.receipt_bytes)?;
    let mut command = Command::new(&config.verifier);
    stage::configure_process_group(&mut command);
    let mut child = command
        .arg("evidence")
        .arg("--view")
        .arg(view_path)
        .arg("--receipt")
        .arg(receipt_path)
        .arg("--source")
        .arg(&config.wheel)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    if !stage::wait_for_child(&mut child, "independent evidence verifier")?.success() {
        return Err("independent evidence verification failed".into());
    }
    let evidence_seconds = started.elapsed().as_secs_f64();
    fs::remove_file(&config.wheel)?;
    if fs::symlink_metadata(&config.wheel).is_ok() {
        return Err("source remained accessible".into());
    }
    let archive = outcome
        .into_verified_archive()
        .ok_or("verified capability absent")?;
    let members = inventory(&archive)?;
    if inventory_digest(&members)? != config.inventory_sha256 {
        return Err("verified inventory changed".into());
    }
    let mut retention_outcomes = Vec::new();
    for pin in &config.paths {
        if !members.contains(pin) {
            return Err("retention pin differs from verified member".into());
        }
        retention_outcomes.push(
            json!({"path": pin.path, "status": format!("{:?}", archive.retention_status(&pin.path)),
            "retained_bytes": archive.retained_member(&pin.path).map_or(0, |bytes| bytes.len())}),
        );
    }
    let retained_bytes = archive.retained_bytes();
    let retained_members = config
        .paths
        .iter()
        .filter(|pin| archive.retained_member(&pin.path).is_some())
        .count();
    let started = Instant::now();
    let evaluation = evaluate_wheel(&filename, &archive, WheelLimits::default());
    let evaluation_seconds = started.elapsed().as_secs_f64();
    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = evaluation
    else {
        return Err(format!("wheel evaluation failed: {evaluation:?}").into());
    };
    let started = Instant::now();
    let prepared = stage::prepare_wheel_source(
        &private,
        &archive,
        &artifact,
        &plan,
        &identities,
        &canonical.receipt_digest,
        stage::PreparationTarget {
            handoff: stage::HandoffTarget::Copyable,
            interpreter: Path::new("/usr/bin/python3"),
        },
    )?;
    let staging_seconds = started.elapsed().as_secs_f64();
    drop(archive);
    let installation = prepared.install(
        Path::new("/usr/bin/python3"),
        &config.installer_root,
        &config.output_root,
        &plan,
        &artifact,
    )?;
    if fs::symlink_metadata(&config.wheel).is_ok() {
        return Err("source reappeared during consumption".into());
    }
    let files = installation
        .files
        .iter()
        .map(|file| {
            json!({"scheme": file.scheme, "relative_path": file.relative_path,
        "sha256": file.sha256, "size": file.size, "executable": file.executable})
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"schema": "sealr.retention-experiment-case.v1", "strategy": config.strategy,
        "source_deleted_before_evaluation": true, "source_deleted_before_member_consumption": true,
        "independent_evidence_verified": true, "requested_paths": config.paths.len(),
        "requested_bytes": requested_bytes, "retained_members": retained_members,
        "retained_bytes": retained_bytes, "retention_outcomes": retention_outcomes,
        "canonical_view_sha256": canonical.view_digest, "canonical_receipt_sha256": canonical.receipt_digest,
        "source_sha256": identities.source_sha256, "archive_tree_sha256": identities.archive_tree_sha256,
        "artifact_sha256": identities.artifact_sha256, "install_plan_sha256": identities.install_plan_sha256,
        "realization_sha256": installation.realization_sha256, "installed_files": files,
        "phase_seconds": {"admission": admission_seconds, "evidence": evidence_seconds,
            "evaluation": evaluation_seconds, "staging": staging_seconds,
            "installation": installation.installation_seconds, "output_audit": installation.output_audit_seconds}}),
    )
}

fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: retention-experiment inventory ROOT | run CONFIG.json".into());
    }
    let report = if args[0] == "inventory" {
        generate_pins(Path::new(&args[1]))?
    } else if args[0] == "run" {
        consume(serde_json::from_slice(&fs::read(&args[1])?)?)?
    } else {
        return Err("expected inventory or run".into());
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
