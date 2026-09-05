use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sealr::wheel::{
    realize_identity, ExecutableDisposition, InstallScheme, InstallTransform, RealizedOutput,
    RecordBinding, WheelArtifactIR, WheelIdentities, WheelInstallPlan,
};
use sealr::{MemberKind, VerifiedArchive};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INSTALLER_VERSION: &str = "1.0.1";
pub const INSTALLER_WHEEL_SHA256: &str =
    "011d045df8b954ced7dde3a7e42ae4418da40ecda7990f2d11d5ed7c146fd98b";
pub const TARGET_MODEL: &str = "pypa-installer-1.0.1-linux-posix";
pub const INSTALLER_POLICY: &str = "separate-roots-no-bytecode-no-overwrite-v1";
pub const POETRY_TARGET_MODEL: &str = "poetry-2.4.2-installer-1.0.1-linux-posix";
pub const POETRY_INSTALLER_POLICY: &str =
    "poetry-2.4.2-cpython-3.12-venv-no-bytecode-no-overwrite-v1";
pub const POETRY_INSTALLER_METADATA: &str = "Poetry 2.4.2";
pub const PYTHON_INTERPRETER: &str = "/usr/bin/python3";

const MANIFEST_SCHEMA: &str = "sealr.pypa-wheel-source.v1";
const POETRY_MANIFEST_SCHEMA: &str = "sealr.pypa-wheel-source.v2";
const ADAPTER_ID: &str = "pypa-installer-1.0.1-wheel-source";
const REPORT_SCHEMA: &str = "sealr.pypa-wheel-source-report.v1";
const MAX_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct HandoffManifest<'a> {
    schema: &'static str,
    adapter: &'static str,
    installer_version: &'static str,
    installer_wheel_sha256: &'static str,
    canonical_receipt_sha256: &'a str,
    artifact_sha256: &'a str,
    install_plan_sha256: &'a str,
    distribution: &'a str,
    version: &'a str,
    dist_info_dir: &'a str,
    data_dir: &'a str,
    interpreter: String,
    target_model: &'static str,
    installer_policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_installer: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_model: Option<&'static str>,
    members: Vec<HandoffMember>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffTarget {
    Copyable,
    Poetry242Update,
}

pub struct PreparationTarget<'a> {
    pub handoff: HandoffTarget,
    pub interpreter: &'a Path,
}

impl HandoffTarget {
    pub fn target_model(self) -> &'static str {
        match self {
            Self::Copyable => TARGET_MODEL,
            Self::Poetry242Update => POETRY_TARGET_MODEL,
        }
    }

    pub fn installer_policy(self) -> &'static str {
        match self {
            Self::Copyable => INSTALLER_POLICY,
            Self::Poetry242Update => POETRY_INSTALLER_POLICY,
        }
    }

    fn additional_installer(self) -> Option<&'static str> {
        match self {
            Self::Copyable => None,
            Self::Poetry242Update => Some(POETRY_INSTALLER_METADATA),
        }
    }

    fn manifest_schema(self) -> &'static str {
        match self {
            Self::Copyable => MANIFEST_SCHEMA,
            Self::Poetry242Update => POETRY_MANIFEST_SCHEMA,
        }
    }

    fn destination_model(self) -> Option<&'static str> {
        match self {
            Self::Copyable => None,
            Self::Poetry242Update => Some("poetry-2.4.2-cpython-3.12-venv-v1"),
        }
    }
}

#[derive(Serialize)]
struct HandoffMember {
    index: usize,
    path: String,
    blob: String,
    sha256: String,
    size: u64,
    record_hash: String,
    record_size: String,
    executable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct InstalledFile {
    pub scheme: String,
    pub relative_path: String,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeReport {
    schema: String,
    adapter: String,
    installer_version: String,
    manifest_sha256: String,
    canonical_receipt_sha256: String,
    wheel_open_audit: String,
    repeatable_member_reads: usize,
    installed_files: Vec<InstalledFile>,
}

pub struct PrivateRoot {
    path: PathBuf,
}

impl PrivateRoot {
    pub fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let parent = fs::canonicalize(std::env::temp_dir())?;
        require_trusted_ancestor_chain(&parent, "temporary staging parent")?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        for attempt in 0..128_u32 {
            let path = parent.join(format!(
                "sealr-wheel-source-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_private_permissions(&path)?;
                    verify_private_directory(&path)?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not create an exclusive private staging root".into())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct PreparedWheelSource<'a> {
    root: &'a PrivateRoot,
    manifest_path: PathBuf,
    manifest_sha256: String,
    receipt_sha256: String,
    member_count: usize,
    target: HandoffTarget,
}

pub struct InstallationResult {
    pub files: Vec<InstalledFile>,
    pub realization_sha256: String,
}

pub fn prepare_wheel_source<'a>(
    root: &'a PrivateRoot,
    archive: &VerifiedArchive,
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    identities: &WheelIdentities,
    receipt_sha256: &str,
    target: PreparationTarget<'_>,
) -> Result<PreparedWheelSource<'a>, Box<dyn std::error::Error>> {
    validate_digest(receipt_sha256, "canonical receipt SHA-256")?;
    validate_digest(&identities.artifact_sha256, "artifact SHA-256")?;
    validate_digest(&identities.install_plan_sha256, "install-plan SHA-256")?;
    if plan.artifact_sha256() != identities.artifact_sha256 {
        return Err("wheel plan and artifact identity disagree".into());
    }
    preflight_plan(plan)?;

    let members_root = root.path().join("members");
    fs::create_dir(&members_root)?;
    set_private_permissions(&members_root)?;

    let records = artifact
        .record
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let record_path = format!("{}/RECORD", artifact.dist_info_root);
    let signature_paths = [format!("{record_path}.jws"), format!("{record_path}.p7s")];

    let mut total = 0_u64;
    let mut preflight = Vec::new();
    for (index, member) in archive.members().iter().enumerate() {
        if matches!(member.kind, MemberKind::Directory) {
            continue;
        }
        let size = member
            .actual_uncomp_size
            .ok_or("verified member lacks measured size")?;
        if size > MAX_MEMBER_BYTES {
            return Err(format!(
                "{} exceeds the {MAX_MEMBER_BYTES}-byte member cap",
                member.canonical_path
            )
            .into());
        }
        total = total
            .checked_add(size)
            .ok_or("verified member byte total overflowed")?;
        if total > MAX_TOTAL_BYTES {
            return Err(
                format!("verified members exceed the {MAX_TOTAL_BYTES}-byte total cap").into(),
            );
        }
        let digest = member
            .content_sha256
            .as_deref()
            .ok_or("verified member lacks SHA-256")?;
        validate_digest(digest, "verified member SHA-256")?;
        let record = records.get(member.canonical_path.as_str()).copied();
        if record.is_none()
            && !signature_paths
                .iter()
                .any(|path| path == &member.canonical_path)
        {
            return Err(
                format!("{} is absent from the bound RECORD", member.canonical_path).into(),
            );
        }
        preflight.push((index, member, size, digest.to_owned(), record));
    }

    let mut members = Vec::with_capacity(preflight.len());
    for (index, member, size, digest, record) in preflight {
        let bytes = archive.read_member(&member.canonical_path, MAX_MEMBER_BYTES)?;
        if u64::try_from(bytes.len()).ok() != Some(size) || hex_sha256(&bytes) != digest {
            return Err(format!(
                "verified read disagrees with bound evidence for {}",
                member.canonical_path
            )
            .into());
        }
        let blob = format!("{index:06}.bin");
        write_new(&members_root.join(&blob), &bytes)?;
        let (record_hash, record_size) = match record {
            Some(record) => (
                record_hash(record)?,
                record
                    .size
                    .map_or_else(String::new, |value| value.to_string()),
            ),
            None => (String::new(), String::new()),
        };
        members.push(HandoffMember {
            index,
            path: member.canonical_path.clone(),
            blob,
            sha256: digest,
            size,
            record_hash,
            record_size,
            executable: member
                .container_facts()
                .ok_or("wheel member lacks container facts")?
                .unix_regular_executable(),
        });
    }

    let effective_data_dir = artifact.data_root.clone().unwrap_or_else(|| {
        format!(
            "{}-{}.data",
            artifact.filename.normalized_distribution, artifact.filename.normalized_version
        )
    });
    let manifest = HandoffManifest {
        schema: target.handoff.manifest_schema(),
        adapter: ADAPTER_ID,
        installer_version: INSTALLER_VERSION,
        installer_wheel_sha256: INSTALLER_WHEEL_SHA256,
        canonical_receipt_sha256: receipt_sha256,
        artifact_sha256: &identities.artifact_sha256,
        install_plan_sha256: &identities.install_plan_sha256,
        distribution: &artifact.filename.distribution,
        version: &artifact.filename.version,
        dist_info_dir: &artifact.dist_info_root,
        data_dir: &effective_data_dir,
        interpreter: target
            .interpreter
            .to_str()
            .ok_or("target interpreter path must be UTF-8")?
            .to_owned(),
        target_model: target.handoff.target_model(),
        installer_policy: target.handoff.installer_policy(),
        additional_installer: target.handoff.additional_installer(),
        destination_model: target.handoff.destination_model(),
        members,
    };
    let mut bytes = serde_json::to_vec(&manifest)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(format!("handoff manifest exceeds {MAX_MANIFEST_BYTES} bytes").into());
    }
    let manifest_sha256 = hex_sha256(&bytes);
    let manifest_path = root.path().join("manifest.json");
    write_new(&manifest_path, &bytes)?;

    Ok(PreparedWheelSource {
        root,
        manifest_path,
        manifest_sha256,
        receipt_sha256: receipt_sha256.to_owned(),
        member_count: manifest.members.len(),
        target: target.handoff,
    })
}

impl PreparedWheelSource<'_> {
    pub fn preflight(
        &self,
        python: &Path,
        installer_root: &Path,
        output_root: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !matches!(self.target, HandoffTarget::Poetry242Update) {
            return Err("preflight is reserved for the Poetry 2.4.2 target".into());
        }
        self.validate_invocation(python, installer_root, output_root)?;
        let bridge_path = self.ensure_bridge()?;
        let report_path = self.root.path().join("preflight-report-unused.json");
        let mut command = Command::new(python);
        configure_process_group(&mut command);
        let mut child = command
            .arg("-I")
            .arg(&bridge_path)
            .arg(&self.manifest_path)
            .arg(&self.manifest_sha256)
            .arg(&self.receipt_sha256)
            .arg(installer_root)
            .arg(output_root)
            .arg(&report_path)
            .arg("--preflight-only")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let status = wait_for_child(&mut child, "WheelSource preflight bridge")?;
        if !status.success() {
            return Err(format!("WheelSource preflight bridge failed with {status}").into());
        }
        if report_path.exists() || fs::symlink_metadata(report_path).is_ok() {
            return Err("WheelSource preflight unexpectedly wrote a report".into());
        }
        Ok(())
    }

    pub fn install(
        self,
        python: &Path,
        installer_root: &Path,
        output_root: &Path,
        plan: &WheelInstallPlan,
        artifact: &WheelArtifactIR,
    ) -> Result<InstallationResult, Box<dyn std::error::Error>> {
        self.validate_invocation(python, installer_root, output_root)?;
        let bridge_path = self.ensure_bridge()?;
        let report_path = self.root.path().join("report.json");

        let mut command = Command::new(python);
        configure_process_group(&mut command);
        let mut child = command
            .arg("-I")
            .arg(&bridge_path)
            .arg(&self.manifest_path)
            .arg(&self.manifest_sha256)
            .arg(&self.receipt_sha256)
            .arg(installer_root)
            .arg(output_root)
            .arg(&report_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let status = wait_for_child(&mut child, "WheelSource bridge")?;
        if !status.success() {
            return Err(format!("WheelSource bridge failed with {status}").into());
        }

        let report_metadata = fs::symlink_metadata(&report_path)?;
        if report_metadata.file_type().is_symlink()
            || !report_metadata.is_file()
            || report_metadata.len() > MAX_REPORT_BYTES
        {
            return Err("WheelSource bridge report is not a bounded regular file".into());
        }
        let report: BridgeReport = serde_json::from_slice(&fs::read(&report_path)?)?;
        if report.schema != REPORT_SCHEMA
            || report.adapter != ADAPTER_ID
            || report.installer_version != INSTALLER_VERSION
            || report.manifest_sha256 != self.manifest_sha256
            || report.canonical_receipt_sha256 != self.receipt_sha256
            || report.wheel_open_audit != "enforced"
            || report.repeatable_member_reads != self.member_count
        {
            return Err(format!(
                "WheelSource bridge report disagrees with the contract: {report:?}"
            )
            .into());
        }

        let mut reported = report.installed_files;
        reported.sort();
        let mut observed = match self.target {
            HandoffTarget::Copyable => enumerate_installation(output_root)?,
            HandoffTarget::Poetry242Update => {
                verify_poetry_outputs(output_root, artifact, &reported)?
            }
        };
        observed.sort();
        if observed != reported {
            return Err("independent output verification disagrees with the bridge report".into());
        }
        validate_installed_targets(artifact, plan, &observed, self.target)?;
        let outputs = observed
            .iter()
            .map(|file| {
                Ok(RealizedOutput::new(
                    parse_scheme(&file.scheme)?,
                    file.relative_path.clone(),
                    file.sha256.clone(),
                    file.size,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let realization_sha256 = realize_identity(
            plan,
            self.target.target_model(),
            self.target.installer_policy(),
            &outputs,
        )?;
        Ok(InstallationResult {
            files: observed,
            realization_sha256,
        })
    }

    fn validate_invocation(
        &self,
        python: &Path,
        installer_root: &Path,
        output_root: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if python != Path::new(PYTHON_INTERPRETER) {
            return Err(format!("Python must be exactly {PYTHON_INTERPRETER}").into());
        }
        require_real_directory(installer_root, "installer root")?;
        if matches!(self.target, HandoffTarget::Poetry242Update) {
            validate_existing_poetry_venv(output_root)?;
        } else if output_root.exists() || fs::symlink_metadata(output_root).is_ok() {
            return Err("output root must not already exist".into());
        }
        Ok(())
    }

    fn ensure_bridge(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = self.root.path().join("wheel_source.py");
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || fs::read(&path)? != include_bytes!("wheel_source.py")
                {
                    return Err("staged WheelSource bridge changed after creation".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_new(&path, include_bytes!("wheel_source.py"))?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(path)
    }
}

fn preflight_plan(plan: &WheelInstallPlan) -> Result<(), Box<dyn std::error::Error>> {
    for entry in plan.entries() {
        scheme_name(&entry.scheme)?;
        expected_executable(&entry.executable)?;
        match &entry.transform {
            InstallTransform::Copy
            | InstallTransform::RewritePythonShebang
            | InstallTransform::GenerateConsoleWrapper
            | InstallTransform::GenerateGuiWrapper => {}
            _ => return Err("wheel plan contains an unsupported future transform".into()),
        }
    }
    Ok(())
}

fn validate_installed_targets(
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    installed: &[InstalledFile],
    target: HandoffTarget,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected = BTreeMap::new();
    for entry in plan.entries() {
        let scheme = scheme_name(&entry.scheme)?.to_owned();
        let key = (scheme, entry.relative_path.clone());
        if expected
            .insert(key, expected_executable(&entry.executable)?)
            .is_some()
        {
            return Err("wheel plan contains a duplicate output".into());
        }
    }
    let record_scheme = if artifact.wheel.root_is_purelib {
        "purelib"
    } else {
        "platlib"
    };
    expected.insert(
        (
            record_scheme.to_owned(),
            format!("{}/RECORD", artifact.dist_info_root),
        ),
        false,
    );
    if target.additional_installer().is_some() {
        expected.insert(
            (
                record_scheme.to_owned(),
                format!("{}/INSTALLER", artifact.dist_info_root),
            ),
            false,
        );
    }

    let mut actual = BTreeSet::new();
    for file in installed {
        let key = (file.scheme.clone(), file.relative_path.clone());
        let Some(executable) = expected.get(&key) else {
            return Err(format!(
                "installation produced an unexpected output: {}/{}",
                file.scheme, file.relative_path
            )
            .into());
        };
        if file.executable != *executable {
            return Err(format!(
                "installed executable mode disagrees for {}/{}",
                file.scheme, file.relative_path
            )
            .into());
        }
        if !actual.insert(key) {
            return Err("installation report contains a duplicate output".into());
        }
    }
    let expected_keys = expected.into_keys().collect::<BTreeSet<_>>();
    if actual != expected_keys {
        return Err("installed paths disagree with the complete plan plus final RECORD".into());
    }
    Ok(())
}

fn expected_executable(
    disposition: &ExecutableDisposition,
) -> Result<bool, Box<dyn std::error::Error>> {
    match disposition {
        ExecutableDisposition::NotExecutable => Ok(false),
        ExecutableDisposition::SourceExecutable | ExecutableDisposition::GeneratedWrapper => {
            Ok(true)
        }
        _ => Err("wheel plan contains an unsupported future executable disposition".into()),
    }
}

fn scheme_name(scheme: &InstallScheme) -> Result<&'static str, Box<dyn std::error::Error>> {
    match scheme {
        InstallScheme::Purelib => Ok("purelib"),
        InstallScheme::Platlib => Ok("platlib"),
        InstallScheme::Scripts => Ok("scripts"),
        InstallScheme::Headers => Ok("headers"),
        InstallScheme::Data => Ok("data"),
        _ => Err("wheel plan contains an unsupported future install scheme".into()),
    }
}

fn parse_scheme(value: &str) -> Result<InstallScheme, Box<dyn std::error::Error>> {
    match value {
        "purelib" => Ok(InstallScheme::Purelib),
        "platlib" => Ok(InstallScheme::Platlib),
        "scripts" => Ok(InstallScheme::Scripts),
        "headers" => Ok(InstallScheme::Headers),
        "data" => Ok(InstallScheme::Data),
        _ => Err(format!("unknown install scheme: {value}").into()),
    }
}

fn enumerate_installation(root: &Path) -> Result<Vec<InstalledFile>, Box<dyn std::error::Error>> {
    require_real_directory(root, "output root")?;
    validate_scheme_roots(root)?;
    let mut outputs = Vec::new();
    let mut total = 0_u64;
    for scheme in ["purelib", "platlib", "scripts", "headers", "data"] {
        let scheme_root = root.join(scheme);
        require_real_directory(&scheme_root, "scheme root")?;
        let mut pending = vec![scheme_root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err(
                        format!("installed output is a symbolic link: {}", path.display()).into(),
                    );
                }
                if metadata.is_dir() {
                    pending.push(path);
                    continue;
                }
                if !metadata.is_file() {
                    return Err(format!(
                        "installed output is not a regular file: {}",
                        path.display()
                    )
                    .into());
                }
                require_single_link(&metadata, &path)?;
                total = total
                    .checked_add(metadata.len())
                    .ok_or("installed byte total overflowed")?;
                if outputs.len() >= 65_536 || total > 256 * 1024 * 1024 {
                    return Err("installed outputs exceed reporting limits".into());
                }
                let relative = path
                    .strip_prefix(&scheme_root)?
                    .to_str()
                    .ok_or("installed output path is not UTF-8")?
                    .replace('\\', "/");
                if relative.is_empty()
                    || relative
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                {
                    return Err("installed output path is not canonical".into());
                }
                let bytes = fs::read(&path)?;
                outputs.push(InstalledFile {
                    scheme: scheme.to_owned(),
                    relative_path: relative,
                    sha256: hex_sha256(&bytes),
                    size: metadata.len(),
                    executable: is_executable(&metadata),
                });
            }
        }
    }
    Ok(outputs)
}

fn verify_poetry_outputs(
    root: &Path,
    artifact: &WheelArtifactIR,
    reported: &[InstalledFile],
) -> Result<Vec<InstalledFile>, Box<dyn std::error::Error>> {
    validate_existing_poetry_venv(root)?;
    let mut physical_targets = BTreeSet::new();
    for file in reported {
        let relative = Path::new(&file.relative_path);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err("Poetry output report contains a non-canonical relative path".into());
        }
        let scheme_root = match file.scheme.as_str() {
            "purelib" | "platlib" => root.join("lib/python3.12/site-packages"),
            "scripts" => root.join("bin"),
            "headers" => root
                .join("include/site/python3.12")
                .join(&artifact.filename.distribution),
            "data" => root.to_owned(),
            value => return Err(format!("unknown Poetry install scheme: {value}").into()),
        };
        let path = scheme_root.join(relative);
        if !physical_targets.insert(path.clone()) {
            return Err("Poetry outputs alias the same physical target".into());
        }
        require_no_symlink_ancestors(&scheme_root, &path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("Poetry output is not a regular file: {}", path.display()).into());
        }
        require_single_link(&metadata, &path)?;
        if metadata.len() != file.size {
            return Err(format!("Poetry output size disagrees: {}", path.display()).into());
        }
        let bytes = fs::read(&path)?;
        if hex_sha256(&bytes) != file.sha256 {
            return Err(format!("Poetry output digest disagrees: {}", path.display()).into());
        }
        if is_executable(&metadata) != file.executable {
            return Err(format!("Poetry output mode disagrees: {}", path.display()).into());
        }
    }
    Ok(reported.to_vec())
}

fn require_no_symlink_ancestors(
    scheme_root: &Path,
    target: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = target.parent().ok_or("Poetry output has no parent")?;
    let relative = parent.strip_prefix(scheme_root)?;
    let mut current = scheme_root.to_owned();
    require_real_directory(&current, "Poetry scheme root")?;
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err("Poetry output ancestor is not canonical".into());
        };
        current.push(component);
        require_real_directory(&current, "Poetry output ancestor")?;
    }
    Ok(())
}

fn validate_scheme_roots(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let expected = ["purelib", "platlib", "scripts", "headers", "data"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "installer output root contains a non-directory entry: {}",
                path.display()
            )
            .into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "installer output root contains a non-UTF-8 scheme name")?;
        if !observed.insert(name) {
            return Err("installer output root contains duplicate scheme names".into());
        }
    }
    if observed != expected {
        return Err("installer output root disagrees with the five exact scheme roots".into());
    }
    Ok(())
}

pub fn validate_existing_poetry_venv(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    require_real_directory(root, "Poetry virtual environment root")?;
    require_real_directory(
        &root.join("bin"),
        "Poetry virtual environment bin directory",
    )?;
    require_real_directory(
        &root.join("lib/python3.12/site-packages"),
        "Poetry virtual environment site-packages",
    )?;
    let python = fs::symlink_metadata(root.join("bin/python"))?;
    if !python.is_file() && !python.file_type().is_symlink() {
        return Err("Poetry virtual environment interpreter is not a file or link".into());
    }
    Ok(())
}

pub fn wait_for_child(
    child: &mut std::process::Child,
    label: &str,
) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    wait_for_child_with(
        child,
        label,
        CHILD_TIMEOUT,
        std::process::Child::try_wait,
        terminate_process_group,
    )
}

fn wait_for_child_with<P, T>(
    child: &mut std::process::Child,
    label: &str,
    timeout: Duration,
    mut poll: P,
    mut terminate_group: T,
) -> Result<ExitStatus, Box<dyn std::error::Error>>
where
    P: FnMut(&mut std::process::Child) -> std::io::Result<Option<ExitStatus>>,
    T: FnMut(&mut std::process::Child) -> std::io::Result<()>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match poll(child) {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                return terminate_and_reap(
                    child,
                    label,
                    format!("child status polling failed: {error}"),
                    &mut terminate_group,
                );
            }
        }
        if Instant::now() >= deadline {
            return terminate_and_reap(
                child,
                label,
                format!("exceeded its {}-second deadline", timeout.as_secs()),
                &mut terminate_group,
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn terminate_and_reap<T>(
    child: &mut std::process::Child,
    label: &str,
    reason: String,
    terminate_group: &mut T,
) -> Result<ExitStatus, Box<dyn std::error::Error>>
where
    T: FnMut(&mut std::process::Child) -> std::io::Result<()>,
{
    let group_result = terminate_group(child).map_err(|error| error.to_string());
    let direct_result = child.kill().map_err(|error| error.to_string());
    let reap_deadline = Instant::now() + CHILD_REAP_TIMEOUT;
    let mut last_poll_error = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "{label} {reason}; process-group termination: {}; direct-child termination: {}; reaped with {status}",
                    operation_result(&group_result),
                    operation_result(&direct_result),
                )
                .into());
            }
            Ok(None) => {}
            Err(error) => last_poll_error = Some(error.to_string()),
        }
        if Instant::now() >= reap_deadline {
            return Err(format!(
                "{label} {reason}; process-group termination: {}; direct-child termination: {}; reap was not confirmed within {} seconds{}",
                operation_result(&group_result),
                operation_result(&direct_result),
                CHILD_REAP_TIMEOUT.as_secs(),
                last_poll_error.map_or_else(String::new, |error| format!("; last reap poll failed: {error}")),
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn operation_result(result: &Result<(), String>) -> &str {
    match result {
        Ok(()) => "succeeded",
        Err(error) => error,
    }
}

pub fn configure_process_group(_command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        _command.process_group(0);
    }
}

#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) -> std::io::Result<()> {
    let process_group = i32::try_from(child.id())
        .map_err(|_| std::io::Error::other("child process ID exceeds i32"))?;
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(all(test, unix))]
mod child_deadline_tests {
    use super::*;

    fn sleeping_child() -> std::process::Child {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exec sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        command.spawn().expect("sleeping child starts")
    }

    #[test]
    fn poll_failure_terminates_and_reaps_the_child() {
        let mut child = sleeping_child();
        let error = wait_for_child_with(
            &mut child,
            "test child",
            Duration::from_secs(1),
            |_| Err(std::io::Error::other("injected poll failure")),
            terminate_process_group,
        )
        .expect_err("poll failure must fail closed");
        assert!(error.to_string().contains("child status polling failed"));
        assert!(child
            .try_wait()
            .expect("postcondition poll succeeds")
            .is_some());
    }

    #[test]
    fn group_termination_failure_uses_direct_kill_and_reaps() {
        let mut child = sleeping_child();
        let error = wait_for_child_with(
            &mut child,
            "test child",
            Duration::ZERO,
            std::process::Child::try_wait,
            |_| Err(std::io::Error::other("injected group termination failure")),
        )
        .expect_err("deadline must fail closed");
        let detail = error.to_string();
        assert!(detail.contains("injected group termination failure"));
        assert!(detail.contains("direct-child termination: succeeded"));
        assert!(child
            .try_wait()
            .expect("postcondition poll succeeds")
            .is_some());
    }

    #[test]
    fn timeout_kills_same_group_descendants() {
        let root = PrivateRoot::create().expect("private test root exists");
        let ready = root.path().join("ready");
        let escaped = root.path().join("escaped");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("(sleep 0.4; printf escaped > \"$2\") & printf ready > \"$1\"; wait")
            .arg("sealr-child-deadline-test")
            .arg(&ready)
            .arg(&escaped)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let mut child = command.spawn().expect("descendant fixture starts");
        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !ready.exists() {
            assert!(
                Instant::now() < ready_deadline,
                "descendant fixture did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let error = wait_for_child_with(
            &mut child,
            "test child group",
            Duration::ZERO,
            std::process::Child::try_wait,
            terminate_process_group,
        )
        .expect_err("deadline must fail closed");
        assert!(error
            .to_string()
            .contains("process-group termination: succeeded"));
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            !escaped.exists(),
            "a same-group descendant survived cancellation"
        );
    }
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn require_single_link(
    metadata: &fs::Metadata,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() != 1 {
        return Err(format!(
            "installed output has multiple hard links: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_single_link(
    _metadata: &fs::Metadata,
    _path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory: {}", path.display()).into());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not lowercase hexadecimal").into());
    }
    Ok(())
}

fn record_hash(record: &RecordBinding) -> Result<String, Box<dyn std::error::Error>> {
    let Some(value) = record.sha256.as_deref() else {
        return Ok(String::new());
    };
    validate_digest(value, "RECORD SHA-256")?;
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(format!("sha256={}", base64url(&digest)))
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 63) as usize] as char);
        }
    }
    output
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn require_trusted_ancestor_chain(
    path: &Path,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_uid = unsafe { libc::geteuid() };
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("{label} has a non-directory ancestor").into());
        }
        let mode = metadata.permissions().mode();
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;
        let writable_by_others = mode & 0o022 != 0;
        let trusted_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        if !trusted_owner || writable_by_others && !trusted_sticky {
            return Err(format!(
                "{label} permits untrusted namespace mutation: {}",
                ancestor.display()
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_trusted_ancestor_chain(
    _path: &Path,
    _label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("private staging root ownership or mode verification failed".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_directory(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}
