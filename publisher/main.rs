//! A narrow publisher decision over an admitted capability.
//!
//! The supplied wheel is preserved. A private copy is admitted, independently
//! checked, and deleted before wheel evaluation and the content gate run.
//! This example prepares an integration; it is not Deepr's production gate.

#[allow(dead_code)]
#[path = "../handoff/stage.rs"]
mod stage;

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelIdentities, WheelLimits};
use sealr::{
    apply_supervised, AdmissionStatus, ApplyOptions, EffectStatus, LinuxWorker, MemberKind,
    Outcome, Policy, Request, RetentionPlan, Source, SupervisionError, SupervisionErrorKind,
    VerificationStatus, VerifiedArchive, ZipInterpretationProfile,
};
use serde::Serialize;

const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const REQUIRED_FILES: [&str; 5] = [
    "deepr/web/frontend/dist/index.html",
    "deepr/config/system_message.json",
    "deepr/skills/recon/skill.yaml",
    "deepr/skills/recon/prompt.md",
    "deepr/templates/documentation_research.md",
];
const ASSETS_PREFIX: &str = "deepr/web/frontend/dist/assets/";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FailureStage {
    Setup,
    Acquisition,
    Admission,
    Evidence,
    SourceRemoval,
    WheelEvaluation,
    Content,
}

/// Machine decisions use stage, code, and finding_codes. Detail is diagnostic
/// text and may contain platform-specific errors or private temporary paths.
#[derive(Debug, Serialize)]
struct GateFailure {
    schema: &'static str,
    accepted: bool,
    stage: FailureStage,
    code: &'static str,
    detail: String,
    finding_codes: Vec<String>,
    private_source_deleted_before_evaluation: bool,
    installed_files: usize,
}

impl GateFailure {
    fn new(stage: FailureStage, code: &'static str, detail: impl ToString) -> Self {
        Self {
            schema: "sealr.deepr-content-gate-failure.v1",
            accepted: false,
            stage,
            code,
            detail: detail.to_string(),
            finding_codes: Vec::new(),
            private_source_deleted_before_evaluation: false,
            installed_files: 0,
        }
    }

    fn with_findings(mut self, codes: impl IntoIterator<Item = String>) -> Self {
        self.finding_codes = codes
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self
    }

    fn after_source_removal(mut self) -> Self {
        self.private_source_deleted_before_evaluation = true;
        self
    }

    fn supervised(stage: FailureStage, error: SupervisionError) -> Self {
        let code = match error.kind() {
            SupervisionErrorKind::IsolationUnavailable => "isolation-unavailable",
            SupervisionErrorKind::HelperArtifact => "worker-artifact",
            SupervisionErrorKind::Spawn => "worker-spawn",
            SupervisionErrorKind::Authentication => "worker-authentication",
            SupervisionErrorKind::RestrictionUnavailable => "worker-restriction",
            SupervisionErrorKind::Protocol => "worker-protocol",
            SupervisionErrorKind::TimedOut => "worker-timeout",
            SupervisionErrorKind::WorkerExit => "worker-exit",
            SupervisionErrorKind::Reap => "worker-reap",
            SupervisionErrorKind::Cleanup => "worker-cleanup",
            SupervisionErrorKind::Source => "worker-source",
            SupervisionErrorKind::IntegrityMismatch => "worker-integrity",
            SupervisionErrorKind::Internal => "worker-internal",
            _ => "worker-failure",
        };
        Self::new(stage, code, error)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ContentDecision {
    required_files: usize,
    javascript_files: usize,
    css_files: usize,
}

/// The business consumer receives neither a path nor source bytes. Admission
/// has already established path uniqueness, canonical names, and integrity.
fn check_deepr_content(archive: &VerifiedArchive) -> Result<ContentDecision, GateFailure> {
    let mut files = BTreeSet::new();
    let mut forbidden = BTreeSet::new();
    for member in archive.members() {
        let path = member.canonical_path.as_str();
        if path
            .split('/')
            .any(|part| matches!(part, "node_modules" | "__pycache__"))
            || path.rsplit('/').next() == Some("frontend-dist.zip")
            || path.ends_with(".pyc")
            || path.ends_with(".pyo")
        {
            forbidden.insert(path);
        }
        if member.kind == MemberKind::File {
            files.insert(path);
        }
    }
    if let Some(path) = forbidden.first() {
        return Err(GateFailure::new(
            FailureStage::Content,
            "build-only-member",
            format!("build-only member: {path}"),
        ));
    }
    for path in REQUIRED_FILES {
        if !files.contains(path) {
            return Err(GateFailure::new(
                FailureStage::Content,
                "missing-required-file",
                format!("missing required file: {path}"),
            ));
        }
    }
    let javascript_files = files
        .iter()
        .filter(|path| path.starts_with(ASSETS_PREFIX) && path.ends_with(".js"))
        .count();
    let css_files = files
        .iter()
        .filter(|path| path.starts_with(ASSETS_PREFIX) && path.ends_with(".css"))
        .count();
    if javascript_files == 0 {
        return Err(GateFailure::new(
            FailureStage::Content,
            "missing-javascript",
            "no packaged frontend JavaScript assets",
        ));
    }
    if css_files == 0 {
        return Err(GateFailure::new(
            FailureStage::Content,
            "missing-css",
            "no packaged frontend CSS assets",
        ));
    }
    Ok(ContentDecision {
        required_files: REQUIRED_FILES.len(),
        javascript_files,
        css_files,
    })
}

struct Args {
    wheel: PathBuf,
    worker_manifest: PathBuf,
    verifier: PathBuf,
    retention: RetentionPlan,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn std::error::Error>> {
        let mut values = std::env::args_os().skip(1);
        let mut wheel = None;
        let mut worker_manifest = None;
        let mut verifier = None;
        let mut retention = RetentionPlan::new(256 * 1024, 1024 * 1024);
        while let Some(flag) = values.next() {
            let value = values.next().ok_or("each flag requires a value")?;
            let slot = match flag.to_str() {
                Some("--wheel") => &mut wheel,
                Some("--worker-manifest") => &mut worker_manifest,
                Some("--verifier") => &mut verifier,
                Some("--retain-member") => {
                    retention.add_path(
                        value
                            .into_string()
                            .map_err(|_| "retention path must be UTF-8")?,
                    )?;
                    continue;
                }
                _ => return Err(format!("unknown argument: {}", flag.to_string_lossy()).into()),
            };
            if slot.is_some() {
                return Err(format!("duplicate argument: {}", flag.to_string_lossy()).into());
            }
            *slot = Some(PathBuf::from(value));
        }
        Ok(Self {
            wheel: wheel.ok_or("--wheel is required")?,
            worker_manifest: worker_manifest.ok_or("--worker-manifest is required")?,
            verifier: verifier.ok_or("--verifier is required")?,
            retention,
        })
    }
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    accepted: bool,
    private_source_deleted_before_evaluation: bool,
    installed_files: usize,
    source_sha256: String,
    archive_tree_sha256: String,
    artifact_sha256: String,
    install_plan_sha256: String,
    canonical_view_sha256: String,
    canonical_receipt_sha256: String,
    content: ContentDecision,
    retention: Vec<RetainedPath>,
    retained_bytes: u64,
    admission_seconds: f64,
    evidence_seconds: f64,
    evaluation_seconds: f64,
    content_gate_seconds: f64,
}

#[derive(Serialize)]
struct RetainedPath {
    path: String,
    status: String,
}

struct ConsumerResult {
    identities: WheelIdentities,
    content: ContentDecision,
    evaluation_seconds: f64,
    content_gate_seconds: f64,
}

/// Called only after independent evidence verification and private source removal.
fn consume_after_source_removal(
    filename: &str,
    archive: &VerifiedArchive,
) -> Result<ConsumerResult, GateFailure> {
    let started = Instant::now();
    let identities =
        evaluate_for_gate(filename, archive).map_err(GateFailure::after_source_removal)?;
    let evaluation_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let content = check_deepr_content(archive).map_err(GateFailure::after_source_removal)?;
    Ok(ConsumerResult {
        identities,
        content,
        evaluation_seconds,
        content_gate_seconds: started.elapsed().as_secs_f64(),
    })
}

fn main() -> ExitCode {
    let (report, exit) = match run() {
        Ok(report) => (serde_json::to_string(&report), ExitCode::SUCCESS),
        Err(failure) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "{}: {}",
                failure.code,
                failure.detail
            );
            (serde_json::to_string(&failure), ExitCode::FAILURE)
        }
    };
    match report {
        Ok(report) => match writeln!(std::io::stdout().lock(), "{report}") {
            Ok(()) => exit,
            Err(error) => {
                let _ = writeln!(std::io::stderr().lock(), "report output failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "report encoding failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn require_admitted(outcome: &Outcome) -> Result<&VerifiedArchive, GateFailure> {
    if !matches!(outcome.admission, AdmissionStatus::Admitted)
        || !matches!(outcome.verification, VerificationStatus::Complete)
    {
        return Err(GateFailure::new(
            FailureStage::Admission,
            "archive-not-admitted",
            format!(
                "archive inspection did not complete: {:?}",
                outcome.view.findings
            ),
        )
        .with_findings(
            outcome
                .view
                .findings
                .iter()
                .map(|finding| finding.code.as_str().to_owned()),
        ));
    }
    if !matches!(outcome.effect, EffectStatus::NotRequested) {
        return Err(GateFailure::new(
            FailureStage::Admission,
            "unexpected-effect",
            "the publisher gate requires inspection without a destination effect",
        ));
    }
    outcome.verified_archive().ok_or_else(|| {
        GateFailure::new(
            FailureStage::Admission,
            "capability-unavailable",
            "verified capability unavailable",
        )
    })
}

fn evaluate_for_gate(
    filename: &str,
    archive: &VerifiedArchive,
) -> Result<WheelIdentities, GateFailure> {
    let evaluation = evaluate_wheel(filename, archive, WheelLimits::default());
    let detail = || format!("wheel semantic evaluation failed: {evaluation:?}");
    match &evaluation {
        WheelEvaluation::Denied { findings } => {
            return Err(
                GateFailure::new(FailureStage::WheelEvaluation, "wheel-denied", detail())
                    .with_findings(findings.iter().map(|finding| finding.code.clone())),
            );
        }
        WheelEvaluation::Unsupported { findings } => {
            return Err(GateFailure::new(
                FailureStage::WheelEvaluation,
                "wheel-unsupported",
                detail(),
            )
            .with_findings(findings.iter().map(|finding| finding.code.clone())));
        }
        WheelEvaluation::InfrastructureFailure { .. } => {
            return Err(GateFailure::new(
                FailureStage::WheelEvaluation,
                "wheel-infrastructure",
                detail(),
            ));
        }
        WheelEvaluation::Admitted { .. } => {}
        _ => {
            return Err(GateFailure::new(
                FailureStage::WheelEvaluation,
                "wheel-unrecognized-outcome",
                detail(),
            ));
        }
    }
    let WheelEvaluation::Admitted {
        artifact,
        identities,
        ..
    } = evaluation
    else {
        unreachable!("non-admitted outcomes returned above")
    };
    if artifact.filename.normalized_distribution != "deepr-research" {
        return Err(GateFailure::new(
            FailureStage::WheelEvaluation,
            "distribution-mismatch",
            "this content gate is scoped to the deepr-research distribution",
        ));
    }
    Ok(identities)
}

fn run() -> Result<Report, GateFailure> {
    if !cfg!(target_os = "linux") {
        return Err(GateFailure::new(
            FailureStage::Setup,
            "unsupported-platform",
            "this supervised content-gate example requires Linux",
        ));
    }
    let args = Args::parse()
        .map_err(|error| GateFailure::new(FailureStage::Setup, "invalid-arguments", error))?;
    let filename = args
        .wheel
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            GateFailure::new(
                FailureStage::Setup,
                "invalid-filename",
                "wheel filename must be UTF-8",
            )
        })?;
    let worker = LinuxWorker::load_from_manifest(&args.worker_manifest)
        .map_err(|error| GateFailure::supervised(FailureStage::Setup, error))?;
    let private = stage::PrivateRoot::create()
        .map_err(|error| GateFailure::new(FailureStage::Acquisition, "private-root", error))?;
    let source = private.path().join(filename);
    copy_bounded(&args.wheel, &source)
        .map_err(|error| GateFailure::new(FailureStage::Acquisition, "source-copy", error))?;
    let policy = Policy::default_v1();
    let options = ApplyOptions::new()
        .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1)
        .with_retention(args.retention.clone());
    let started = Instant::now();
    let outcome = apply_supervised(
        Request {
            source: Source::Path(&source),
            policy: &policy,
            dest: None,
        },
        &options,
        &worker,
    )
    .map_err(|error| GateFailure::supervised(FailureStage::Admission, error))?;
    let admission_seconds = started.elapsed().as_secs_f64();
    require_admitted(&outcome)?;
    let started = Instant::now();
    let evidence = outcome.canonical_evidence().map_err(|finding| {
        GateFailure::new(FailureStage::Evidence, "evidence-encoding", finding.detail)
            .with_findings([finding.code.as_str().to_owned()])
    })?;
    let view = private.path().join("view.json");
    let receipt = private.path().join("receipt.json");
    write_new(&view, &evidence.view_bytes)
        .map_err(|error| GateFailure::new(FailureStage::Evidence, "evidence-write", error))?;
    write_new(&receipt, &evidence.receipt_bytes)
        .map_err(|error| GateFailure::new(FailureStage::Evidence, "evidence-write", error))?;
    let mut command = Command::new(&args.verifier);
    stage::configure_process_group(&mut command);
    let mut child = command
        .arg("evidence")
        .arg("--view")
        .arg(&view)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--source")
        .arg(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| GateFailure::new(FailureStage::Evidence, "verifier-spawn", error))?;
    let verifier_status = stage::wait_for_child(&mut child, "independent evidence verifier")
        .map_err(|error| GateFailure::new(FailureStage::Evidence, "verifier-wait", error))?;
    if !verifier_status.success() {
        let code = if verifier_status.code() == Some(1) {
            "verifier-refusal"
        } else {
            "verifier-exit"
        };
        return Err(GateFailure::new(
            FailureStage::Evidence,
            code,
            format!("independent evidence verifier did not accept: {verifier_status}"),
        ));
    }
    let evidence_seconds = started.elapsed().as_secs_f64();
    fs::remove_file(&source)
        .map_err(|error| GateFailure::new(FailureStage::SourceRemoval, "source-delete", error))?;
    if fs::symlink_metadata(&source).is_ok() {
        return Err(GateFailure::new(
            FailureStage::SourceRemoval,
            "source-still-available",
            "private source remained available after deletion",
        ));
    }
    let archive = outcome.into_verified_archive().ok_or_else(|| {
        GateFailure::new(
            FailureStage::Admission,
            "capability-unavailable",
            "verified capability unavailable",
        )
        .after_source_removal()
    })?;
    let ConsumerResult {
        identities,
        content,
        evaluation_seconds,
        content_gate_seconds,
    } = consume_after_source_removal(filename, &archive)?;
    let report = Report {
        schema: "sealr.deepr-content-gate.v1",
        accepted: true,
        private_source_deleted_before_evaluation: true,
        installed_files: 0,
        source_sha256: identities.source_sha256,
        archive_tree_sha256: identities.archive_tree_sha256,
        artifact_sha256: identities.artifact_sha256,
        install_plan_sha256: identities.install_plan_sha256,
        canonical_view_sha256: evidence.view_digest,
        canonical_receipt_sha256: evidence.receipt_digest,
        content,
        retention: args
            .retention
            .paths()
            .map(|path| RetainedPath {
                path: path.to_owned(),
                status: format!("{:?}", archive.retention_status(path)),
            })
            .collect(),
        retained_bytes: archive.retained_bytes(),
        admission_seconds,
        evidence_seconds,
        evaluation_seconds,
        content_gate_seconds,
    };
    Ok(report)
}

fn copy_bounded(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err("wheel must be a regular file, not a link".into());
    }
    let input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err("opened wheel must be a regular file".into());
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(dest)?;
    let bytes = std::io::copy(&mut input.take(MAX_SOURCE_BYTES + 1), &mut output)?;
    if bytes > MAX_SOURCE_BYTES {
        return Err("wheel exceeds the example's 128 MiB acquisition bound".into());
    }
    output.flush()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}
