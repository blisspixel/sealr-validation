//! Controlled repeated reads through the released public supervised capability.
#![allow(clippy::result_large_err)]

#[allow(dead_code)]
#[path = "../../handoff/stage.rs"]
mod stage;

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{
    apply_supervised, apply_with_options, ApplyOptions, LinuxWorker, MemberKind, Policy, Request,
    RetentionPlan, Source, VerifiedArchive, ZipInterpretationProfile,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MEMBER_CAP: u64 = 256 * 1024;
const TOTAL_CAP: u64 = 1024 * 1024;
const SOURCE_CAP: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MemberPin {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    wheel: PathBuf,
    source_sha256: String,
    source_bytes: u64,
    inventory_sha256: String,
    paths: Vec<MemberPin>,
    order: Vec<String>,
    strategy: String,
    worker_manifest: PathBuf,
    verifier: PathBuf,
}

fn options() -> ApplyOptions {
    ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1)
}

fn inventory(archive: &VerifiedArchive) -> Result<Vec<MemberPin>> {
    let mut members = archive
        .members()
        .iter()
        .filter(|member| !matches!(member.kind, MemberKind::Directory))
        .map(|member| {
            Ok(MemberPin {
                path: member.canonical_path.clone(),
                size: member.actual_uncomp_size.ok_or("member size absent")?,
                sha256: member
                    .content_sha256
                    .clone()
                    .ok_or("member digest absent")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    members.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(members)
}

fn source_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > SOURCE_CAP {
        return Err("source must be a bounded regular non-link file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(SOURCE_CAP + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > SOURCE_CAP {
        return Err("source size changed while reading".into());
    }
    Ok(bytes)
}

fn select_paths(members: &[MemberPin]) -> Result<Vec<MemberPin>> {
    let mut selected = members
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
    if selected.len() != 4
        || selected
            .iter()
            .any(|member| member.size == 0 || member.size > MEMBER_CAP)
    {
        return Err("exactly four bounded nonempty semantic members are required".into());
    }
    let mut others = members
        .iter()
        .filter(|member| member.size > 0 && member.size <= MEMBER_CAP && !selected.contains(member))
        .cloned()
        .collect::<Vec<_>>();
    others.sort_by(|left, right| (left.size, &left.path).cmp(&(right.size, &right.path)));
    if others.len() < 4 {
        return Err("not enough ordinary members for the controlled working set".into());
    }
    selected.extend(others.iter().take(2).cloned());
    selected.extend(others.iter().rev().take(2).cloned());
    selected.sort_by(|left, right| left.path.cmp(&right.path));
    validate_paths(&selected)?;
    Ok(selected)
}

fn validate_paths(paths: &[MemberPin]) -> Result<()> {
    if paths.len() != 8
        || paths
            .iter()
            .map(|member| &member.path)
            .collect::<BTreeSet<_>>()
            .len()
            != 8
        || paths
            .iter()
            .any(|member| member.size == 0 || member.size > MEMBER_CAP)
        || paths.iter().map(|member| member.size).sum::<u64>() > TOTAL_CAP
    {
        return Err("working set must contain eight unique bounded nonempty members".into());
    }
    Ok(())
}

fn pinned_inventory(path: &Path) -> Result<Value> {
    let bytes = source_bytes(path)?;
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
    let members = inventory(
        outcome
            .verified_archive()
            .ok_or("inventory admission failed")?,
    )?;
    Ok(
        json!({"schema": "sealr.repeated-read-pins.v1", "source_sha256": stage::hex_sha256(&bytes),
        "source_bytes": bytes.len(), "inventory_sha256": stage::hex_sha256(&serde_json::to_vec(&members)?),
        "regular_members": members.len(), "paths": select_paths(&members)?}),
    )
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn consume(config: Config) -> Result<Value> {
    if !cfg!(target_os = "linux") || !matches!(config.strategy.as_str(), "baseline" | "retained") {
        return Err("a supported Linux retention strategy is required".into());
    }
    validate_paths(&config.paths)?;
    if config.order.len() != 8
        || config.order.iter().collect::<BTreeSet<_>>()
            != config
                .paths
                .iter()
                .map(|member| &member.path)
                .collect::<BTreeSet<_>>()
    {
        return Err("read order must cover the exact selected working set".into());
    }
    let bytes = source_bytes(&config.wheel)?;
    if bytes.len() as u64 != config.source_bytes
        || stage::hex_sha256(&bytes) != config.source_sha256
    {
        return Err("private source differs from the pinned wheel".into());
    }
    drop(bytes);
    let worker = LinuxWorker::load_from_manifest(&config.worker_manifest)?;
    let policy = Policy::default_v1();
    let mut selected_options = options();
    if config.strategy == "retained" {
        let mut retention = RetentionPlan::new(MEMBER_CAP, TOTAL_CAP);
        for member in &config.paths {
            retention.add_path(&member.path)?;
        }
        selected_options = selected_options.with_retention(retention);
    }
    let started = Instant::now();
    let outcome = apply_supervised(
        Request {
            source: Source::Path(&config.wheel),
            policy: &policy,
            dest: None,
        },
        &selected_options,
        &worker,
    )?;
    let admission_seconds = started.elapsed().as_secs_f64();
    if outcome.rejected() {
        return Err("supervised admission rejected the pinned wheel".into());
    }
    let started = Instant::now();
    let canonical = outcome
        .canonical_evidence()
        .map_err(|finding| finding.detail)?;
    let private = stage::PrivateRoot::create()?;
    let view = private.path().join("view.json");
    let receipt = private.path().join("receipt.json");
    write_new(&view, &canonical.view_bytes)?;
    write_new(&receipt, &canonical.receipt_bytes)?;
    let mut command = Command::new(&config.verifier);
    stage::configure_process_group(&mut command);
    let mut child = command
        .arg("evidence")
        .arg("--view")
        .arg(&view)
        .arg("--receipt")
        .arg(&receipt)
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
    let archive = outcome
        .into_verified_archive()
        .ok_or("verified capability absent")?;
    let members = inventory(&archive)?;
    if stage::hex_sha256(&serde_json::to_vec(&members)?) != config.inventory_sha256
        || config.paths.iter().any(|member| !members.contains(member))
    {
        return Err("verified inventory or selected member identity changed".into());
    }
    let expected_retained = if config.strategy == "retained" {
        config.paths.iter().map(|member| member.size).sum::<u64>()
    } else {
        0
    };
    if archive.retained_bytes() != expected_retained
        || config.paths.iter().any(|member| {
            archive.retained_member(&member.path).is_some() != (config.strategy == "retained")
        })
    {
        return Err("requested retention was not fulfilled exactly".into());
    }
    let started = Instant::now();
    let filename = config
        .wheel
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid wheel filename")?;
    let WheelEvaluation::Admitted { identities, .. } =
        evaluate_wheel(filename, &archive, WheelLimits::default())
    else {
        return Err("wheel evaluation was not admitted".into());
    };
    let evaluation_seconds = started.elapsed().as_secs_f64();
    let mut reads = Vec::new();
    for pass in 0..2 {
        for (position, path) in config.order.iter().enumerate() {
            if fs::symlink_metadata(&config.wheel).is_ok() {
                return Err("source pathname reappeared before member consumption".into());
            }
            let pin = config
                .paths
                .iter()
                .find(|member| &member.path == path)
                .ok_or("read pin absent")?;
            let started = Instant::now();
            let bytes = archive.read_member(path, MEMBER_CAP)?;
            let read_seconds = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let output_sha256 = stage::hex_sha256(&bytes);
            if bytes.len() as u64 != pin.size || output_sha256 != pin.sha256 {
                return Err("member output differs from pinned verified evidence".into());
            }
            let digest_check_seconds = started.elapsed().as_secs_f64();
            reads.push(json!({"pass": pass, "position": position, "path": path,
                "output_bytes": bytes.len(), "output_sha256": output_sha256,
                "retention_status": format!("{:?}", archive.retention_status(path)),
                "read_seconds": read_seconds, "digest_check_seconds": digest_check_seconds}));
        }
    }
    if fs::symlink_metadata(&config.wheel).is_ok() {
        return Err("source pathname reappeared during consumption".into());
    }
    Ok(
        json!({"schema": "sealr.repeated-read-case.v1", "strategy": config.strategy,
        "source_deleted_before_evaluation": true, "source_deleted_before_member_consumption": true,
        "independent_evidence_verified": true, "retained_bytes": archive.retained_bytes(),
        "source_sha256": identities.source_sha256, "archive_tree_sha256": identities.archive_tree_sha256,
        "artifact_sha256": identities.artifact_sha256, "install_plan_sha256": identities.install_plan_sha256,
        "canonical_view_sha256": canonical.view_digest, "canonical_receipt_sha256": canonical.receipt_digest,
        "phase_seconds": {"admission": admission_seconds, "evidence": evidence_seconds, "evaluation": evaluation_seconds},
        "reads": reads}),
    )
}

fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: repeated-read-probe inventory WHEEL | run CONFIG.json".into());
    }
    let report = if args[0] == "inventory" {
        pinned_inventory(Path::new(&args[1]))?
    } else if args[0] == "run" {
        consume(serde_json::from_slice(&fs::read(&args[1])?)?)?
    } else {
        return Err("unknown read-probe command".into());
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
