mod stage;

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{
    apply_supervised, ApplyOptions, LinuxWorker, Policy, Request, Source, ZipInterpretationProfile,
};
use serde::Serialize;

use stage::{
    configure_process_group, prepare_wheel_source, validate_existing_poetry_venv, wait_for_child,
    HandoffTarget, PreparationTarget, PrivateRoot,
};

const PREPARED_SCHEMA: &str = "sealr.pypa-wheel-source-prepared.v1";
#[cfg(target_os = "linux")]
const INSTALL_PERMIT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
struct Args {
    wheel: PathBuf,
    worker_manifest: PathBuf,
    verifier: PathBuf,
    python: PathBuf,
    installer_root: PathBuf,
    output_root: PathBuf,
    materialize_raw: Option<PathBuf>,
    poetry_update_context: Option<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut values = std::env::args_os().skip(1);
        let mut wheel = None;
        let mut worker_manifest = None;
        let mut verifier = None;
        let mut python = None;
        let mut installer_root = None;
        let mut output_root = None;
        let mut materialize_raw = None;
        let mut poetry_update_context = None;
        while let Some(flag) = values.next() {
            if flag == "--poetry-2-4-2-update" {
                if poetry_update_context.is_some() {
                    return Err("duplicate argument: --poetry-2-4-2-update".to_owned());
                }
                let value = next_value(&mut values, &flag)?;
                poetry_update_context = Some(
                    value
                        .into_string()
                        .map_err(|_| "Poetry update context must be UTF-8")?,
                );
                continue;
            }
            let slot = match flag.to_str() {
                Some("--consume-wheel") => &mut wheel,
                Some("--worker-manifest") => &mut worker_manifest,
                Some("--verifier") => &mut verifier,
                Some("--python") => &mut python,
                Some("--installer-root") => &mut installer_root,
                Some("--output-root") => &mut output_root,
                Some("--materialize-raw") => &mut materialize_raw,
                _ => return Err(format!("unknown argument: {}", flag.to_string_lossy())),
            };
            if slot.is_some() {
                return Err(format!("duplicate argument: {}", flag.to_string_lossy()));
            }
            *slot = Some(PathBuf::from(next_value(&mut values, &flag)?));
        }
        Ok(Self {
            wheel: wheel.ok_or("--consume-wheel is required")?,
            worker_manifest: worker_manifest.ok_or("--worker-manifest is required")?,
            verifier: verifier.ok_or("--verifier is required")?,
            python: python.ok_or("--python is required")?,
            installer_root: installer_root.ok_or("--installer-root is required")?,
            output_root: output_root.ok_or("--output-root is required")?,
            materialize_raw,
            poetry_update_context,
        })
    }
}

fn next_value(
    values: &mut impl Iterator<Item = OsString>,
    flag: &OsString,
) -> Result<OsString, String> {
    values
        .next()
        .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))
}

#[derive(Serialize)]
struct SuccessReport {
    schema: &'static str,
    source_deleted_before_python: bool,
    target_model: &'static str,
    installer_policy: &'static str,
    canonical_view_sha256: String,
    canonical_receipt_sha256: String,
    source_sha256: String,
    archive_tree_sha256: String,
    artifact_sha256: String,
    install_plan_sha256: String,
    realization_sha256: String,
    installed_files: usize,
    raw_materialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_sha256: Option<String>,
}

#[derive(Serialize)]
struct PreparedReport<'a> {
    schema: &'static str,
    context_sha256: &'a str,
    source_deleted: bool,
    target_model: &'static str,
    installer_policy: &'static str,
    canonical_receipt_sha256: &'a str,
    source_sha256: &'a str,
    archive_tree_sha256: &'a str,
    artifact_sha256: &'a str,
    install_plan_sha256: &'a str,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_os = "linux") {
        return Err("the first packaged WheelSource target requires Linux".into());
    }
    let args = Args::parse().map_err(|detail| {
        format!(
            "{detail}\n{}",
            concat!(
                "usage: pypa_installer_handoff \\\n",
                "  --consume-wheel FILE --worker-manifest ABSOLUTE_PATH --verifier FILE \\\n",
                "  --python /usr/bin/python3 --installer-root DIR --output-root NEW_DIR \\\n",
                "  [--materialize-raw NEW_DIR] [--poetry-2-4-2-update CONTEXT_SHA256]"
            )
        )
    })?;
    require_regular_file(&args.wheel, "wheel")?;
    require_regular_file(&args.verifier, "identity verifier")?;
    require_real_directory(&args.installer_root, "installer root")?;
    let target = if let Some(context) = &args.poetry_update_context {
        validate_sha256(context, "Poetry update context")?;
        if !args.output_root.is_absolute() {
            return Err("Poetry virtual environment root must be absolute".into());
        }
        validate_existing_poetry_venv(&args.output_root)?;
        HandoffTarget::Poetry242Update
    } else {
        require_absent(&args.output_root, "output root")?;
        HandoffTarget::Copyable
    };
    if let Some(raw) = &args.materialize_raw {
        require_absent(raw, "raw materialization root")?;
        if raw == &args.output_root {
            return Err("raw materialization and installer output roots must differ".into());
        }
    }
    let filename = args
        .wheel
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("wheel filename must be UTF-8")?
        .to_owned();
    let worker = LinuxWorker::load_from_manifest(&args.worker_manifest)?;
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let outcome = apply_supervised(
        Request {
            source: Source::Path(&args.wheel),
            policy: &policy,
            dest: args.materialize_raw.as_deref(),
        },
        &options,
        &worker,
    )?;
    if outcome.rejected() {
        return Err(format!("wheel admission failed: {:?}", outcome.view.findings).into());
    }
    if args.materialize_raw.is_some() && !outcome.wrote() {
        return Err("raw materialization was requested but did not commit".into());
    }

    let canonical = outcome
        .canonical_evidence()
        .map_err(|finding| format!("canonical evidence failed: {}", finding.detail))?;
    let private = PrivateRoot::create()?;
    let view_path = private.path().join("view.json");
    let receipt_path = private.path().join("receipt.json");
    write_new(&view_path, &canonical.view_bytes)?;
    write_new(&receipt_path, &canonical.receipt_bytes)?;
    let mut verifier_command = Command::new(&args.verifier);
    configure_process_group(&mut verifier_command);
    let mut verifier = verifier_command
        .arg("evidence")
        .arg("--view")
        .arg(&view_path)
        .arg("--receipt")
        .arg(&receipt_path)
        .arg("--source")
        .arg(&args.wheel)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = wait_for_child(&mut verifier, "independent evidence verifier")?;
    if !status.success() {
        return Err(format!("independent evidence verification failed with {status}").into());
    }

    let evaluation = evaluate_wheel(
        &filename,
        outcome
            .verified_archive()
            .ok_or("admitted wheel did not expose verified authority")?,
        WheelLimits::default(),
    );
    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = evaluation
    else {
        return Err(format!("wheel evaluation did not admit the artifact: {evaluation:?}").into());
    };
    let archive = outcome
        .into_verified_archive()
        .ok_or("verified wheel authority disappeared")?;
    let target_interpreter = match target {
        HandoffTarget::Copyable => args.python.clone(),
        HandoffTarget::Poetry242Update => args.output_root.join("bin/python"),
    };
    let prepared = prepare_wheel_source(
        &private,
        &archive,
        &artifact,
        &plan,
        &identities,
        &canonical.receipt_digest,
        PreparationTarget {
            handoff: target,
            interpreter: &target_interpreter,
        },
    )?;
    drop(archive);

    fs::remove_file(&args.wheel)?;
    if args.wheel.exists() || fs::symlink_metadata(&args.wheel).is_ok() {
        return Err("consumed wheel remained accessible before post-admission installation".into());
    }
    if matches!(target, HandoffTarget::Poetry242Update) {
        prepared.preflight(&args.python, &args.installer_root, &args.output_root)?;
    }
    if let Some(context) = &args.poetry_update_context {
        let prepared_report = PreparedReport {
            schema: PREPARED_SCHEMA,
            context_sha256: context,
            source_deleted: true,
            target_model: target.target_model(),
            installer_policy: target.installer_policy(),
            canonical_receipt_sha256: &canonical.receipt_digest,
            source_sha256: &identities.source_sha256,
            archive_tree_sha256: &identities.archive_tree_sha256,
            artifact_sha256: &identities.artifact_sha256,
            install_plan_sha256: &identities.install_plan_sha256,
        };
        println!("{}", serde_json::to_string(&prepared_report)?);
        std::io::stdout().flush()?;
        wait_for_install_permit(context)?;
    }
    let installation = prepared.install(
        &args.python,
        &args.installer_root,
        &args.output_root,
        &plan,
        &artifact,
    )?;

    let report = SuccessReport {
        schema: "sealr.pypa-wheel-source-example.v1",
        source_deleted_before_python: true,
        target_model: target.target_model(),
        installer_policy: target.installer_policy(),
        canonical_view_sha256: canonical.view_digest,
        canonical_receipt_sha256: canonical.receipt_digest,
        source_sha256: identities.source_sha256,
        archive_tree_sha256: identities.archive_tree_sha256,
        artifact_sha256: identities.artifact_sha256,
        install_plan_sha256: identities.install_plan_sha256,
        realization_sha256: installation.realization_sha256,
        installed_files: installation.files.len(),
        raw_materialized: args.materialize_raw.is_some(),
        context_sha256: args.poetry_update_context,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_install_permit(context: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected = format!("install {context}\n");
    let deadline = Instant::now() + INSTALL_PERMIT_TIMEOUT;
    let mut received = Vec::with_capacity(expected.len());
    let mut stdin = std::io::stdin().lock();
    while received.len() <= expected.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err("Poetry install permit exceeded its 120-second deadline".into());
        }
        let remaining = deadline.saturating_duration_since(now).as_millis();
        let timeout = i32::try_from(remaining).unwrap_or(i32::MAX).max(1);
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result == 0 {
            return Err("Poetry install permit exceeded its 120-second deadline".into());
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("Poetry install permit polling failed: {error}").into());
        }
        let mut byte = [0_u8; 1];
        match stdin.read(&mut byte) {
            Ok(0) => return Err("Poetry install permit input closed before authorization".into()),
            Ok(1) => {
                received.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("Poetry install permit read failed: {error}").into()),
        }
    }
    if received != expected.as_bytes() {
        return Err("Poetry install permit did not match the prepared context".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn wait_for_install_permit(_context: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("the Poetry install permit protocol requires Linux".into())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be a lowercase hexadecimal SHA-256 digest").into());
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular file, not a link: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory: {}", path.display()).into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = unsafe { libc::geteuid() };
        let mode = metadata.permissions().mode();
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;
        let writable_by_others = mode & 0o022 != 0;
        let trusted_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        if !trusted_owner || writable_by_others && !trusted_sticky {
            return Err(format!(
                "{label} permits untrusted namespace mutation: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn require_absent(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(format!("{label} must not already exist: {}", path.display()).into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_real_directory(parent, &format!("{label} parent"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}
