//! WebDAV CLI plugin for voidb-cli

use std::fs;
use std::future::Future;

use async_trait::async_trait;
use chrono::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AgentTransferEvent, AgentTransferOperation, AgentTransferPhase, ConnectionProfileRef,
    TuiLaunchRequest, VoidbError, build_tui_launch_plan,
};

use crate::config::WebDavConfig;
use crate::service::WebDavService;
use crate::tui::{
    WebDavTuiLaunch, WebDavTuiSource, build_webdav_tui_evidence, run_webdav_tui,
    write_webdav_tui_preflight,
};
use crate::types::{SyncMode, SyncOptions};

pub struct WebDavCliPlugin;

pub fn create_webdav_cli_plugin() -> Box<dyn CliPlugin> {
    Box::new(WebDavCliPlugin)
}

#[async_trait]
impl CliPlugin for WebDavCliPlugin {
    fn plugin_id(&self) -> &str {
        "webdav"
    }

    fn name(&self) -> &str {
        "WebDAV"
    }

    fn commands(&self) -> Vec<Command> {
        let conn_arg = Arg::new("connection")
            .short('c')
            .long("connection")
            .required(true)
            .help("Connection name");

        vec![
            Command::new("ls")
                .about("List directory contents")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("path")
                        .default_value("/")
                        .help("Remote directory path"),
                ),
            Command::new("get")
                .about("Download a file")
                .arg(conn_arg.clone())
                .arg(Arg::new("remote").required(true).help("Remote file path"))
                .arg(
                    Arg::new("local")
                        .required(true)
                        .help("Local destination path"),
                )
                .arg(overwrite_arg())
                .arg(transfer_format_arg()),
            Command::new("put")
                .about("Upload a file")
                .arg(conn_arg.clone())
                .arg(Arg::new("local").required(true).help("Local file path"))
                .arg(
                    Arg::new("remote")
                        .required(true)
                        .help("Remote destination path"),
                )
                .arg(overwrite_arg())
                .arg(transfer_format_arg()),
            Command::new("mkdir")
                .about("Create a remote directory")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("path")
                        .required(true)
                        .help("Remote directory path"),
                ),
            Command::new("rm")
                .about("Delete a remote file or directory")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("path")
                        .required(true)
                        .help("Remote path to delete"),
                ),
            Command::new("mv")
                .about("Move or rename a remote item")
                .arg(conn_arg.clone())
                .arg(Arg::new("from").required(true).help("Source path"))
                .arg(Arg::new("to").required(true).help("Destination path"))
                .args(copy_move_args())
                .arg(transfer_format_arg()),
            Command::new("cp")
                .about("Copy a remote item")
                .arg(conn_arg.clone())
                .arg(Arg::new("from").required(true).help("Source path"))
                .arg(Arg::new("to").required(true).help("Destination path"))
                .args(copy_move_args())
                .arg(transfer_format_arg()),
            Command::new("info")
                .about("View file/directory properties")
                .arg(conn_arg.clone())
                .arg(Arg::new("path").default_value("/").help("Remote path")),
            Command::new("test")
                .about("Test WebDAV connection")
                .arg(conn_arg.clone()),
            Command::new("tui")
                .about("Launch the standalone WebDAV browser TUI")
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .value_name("PROFILE")
                        .conflicts_with("connection")
                        .help("Profile name, id:<id>, or name:<name>"),
                )
                .arg(
                    Arg::new("connection")
                        .short('c')
                        .long("connection")
                        .value_name("CONNECTION")
                        .conflicts_with("profile")
                        .help("Legacy connection name"),
                )
                .arg(
                    Arg::new("fixture").long("fixture").value_name("PATH").help(
                        "Load deterministic WebDAV TUI fixture JSON instead of opening a target",
                    ),
                )
                .arg(
                    Arg::new("purpose")
                        .long("purpose")
                        .value_name("PURPOSE")
                        .default_value("browser")
                        .help("Launch purpose, for example browser or transfer"),
                )
                .arg(
                    Arg::new("readonly")
                        .long("readonly")
                        .action(ArgAction::SetTrue)
                        .help("Request read-only behavior where the TUI can enforce it"),
                )
                .arg(
                    Arg::new("no-restore")
                        .long("no-restore")
                        .action(ArgAction::SetTrue)
                        .help("Start without restoring plugin-owned UI state"),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["json"])
                        .help("Emit secret-free preflight JSON and exit"),
                )
                .arg(
                    Arg::new("evidence")
                        .long("evidence")
                        .value_name("PATH")
                        .help("Write fixture-backed standalone WebDAV TUI evidence JSON and exit"),
                ),
            Command::new("pull")
                .about("Sync remote directory to local (remote -> local)")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("remote")
                        .required(true)
                        .help("Remote directory path"),
                )
                .arg(
                    Arg::new("local")
                        .required(true)
                        .help("Local directory path"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Preview changes without executing"),
                )
                .arg(
                    Arg::new("delete")
                        .long("delete")
                        .action(ArgAction::SetTrue)
                        .help("Delete local files not on remote"),
                )
                .arg(
                    Arg::new("exclude")
                        .long("exclude")
                        .action(ArgAction::Append)
                        .help("Glob pattern to exclude"),
                ),
            Command::new("push")
                .about("Sync local directory to remote (local -> remote)")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("local")
                        .required(true)
                        .help("Local directory path"),
                )
                .arg(
                    Arg::new("remote")
                        .required(true)
                        .help("Remote directory path"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Preview changes without executing"),
                )
                .arg(
                    Arg::new("delete")
                        .long("delete")
                        .action(ArgAction::SetTrue)
                        .help("Delete remote files not in local"),
                )
                .arg(
                    Arg::new("exclude")
                        .long("exclude")
                        .action(ArgAction::Append)
                        .help("Glob pattern to exclude"),
                ),
            Command::new("sync")
                .about("Bidirectional sync between remote and local")
                .arg(conn_arg)
                .arg(
                    Arg::new("remote")
                        .required(true)
                        .help("Remote directory path"),
                )
                .arg(
                    Arg::new("local")
                        .required(true)
                        .help("Local directory path"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Preview changes without executing"),
                )
                .arg(
                    Arg::new("delete")
                        .long("delete")
                        .action(ArgAction::SetTrue)
                        .help("Delete files not present on either side"),
                )
                .arg(
                    Arg::new("exclude")
                        .long("exclude")
                        .action(ArgAction::Append)
                        .help("Glob pattern to exclude"),
                ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "ls" => self.handle_ls(matches, ctx).await,
            "get" => self.handle_get(matches, ctx).await,
            "put" => self.handle_put(matches, ctx).await,
            "mkdir" => self.handle_mkdir(matches, ctx).await,
            "rm" => self.handle_rm(matches, ctx).await,
            "mv" => self.handle_mv(matches, ctx).await,
            "cp" => self.handle_cp(matches, ctx).await,
            "info" => self.handle_info(matches, ctx).await,
            "test" => self.handle_test(matches, ctx).await,
            "tui" => self.handle_tui(matches, ctx).await,
            "pull" => self.handle_sync(SyncMode::Pull, matches, ctx).await,
            "push" => self.handle_sync(SyncMode::Push, matches, ctx).await,
            "sync" => self.handle_sync(SyncMode::Sync, matches, ctx).await,
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

impl WebDavCliPlugin {
    fn parse_config(conn_name: &str, ctx: &CliContext) -> Result<WebDavConfig, VoidbError> {
        let config = ctx
            .find_connection(conn_name)
            .ok_or_else(|| VoidbError::Plugin(format!("Connection '{}' not found", conn_name)))?;

        if config.effective_plugin_id() != "webdav" {
            return Err(VoidbError::Plugin(format!(
                "Connection '{}' is not a WebDAV connection (plugin: {})",
                conn_name,
                config.effective_plugin_id()
            )));
        }

        let webdav_config: WebDavConfig = config
            .plugin_config
            .as_ref()
            .ok_or_else(|| VoidbError::Connection("Missing plugin_config".to_string()))
            .and_then(|pc| {
                serde_json::from_value(pc.clone())
                    .map_err(|e| VoidbError::Connection(format!("Invalid WebDAV config: {}", e)))
            })?;

        Ok(webdav_config)
    }

    fn get_config(matches: &ArgMatches, ctx: &CliContext) -> Result<WebDavConfig, VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        Self::parse_config(conn_name, ctx)
    }

    /// Create a Direct-mode service from CLI arguments.
    fn connect(matches: &ArgMatches, ctx: &CliContext) -> Result<WebDavService, VoidbError> {
        let config = Self::get_config(matches, ctx)?;
        WebDavService::new_direct(&config).map_err(|e| VoidbError::Plugin(e.to_string()))
    }

    fn parse_tui_launch(
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<WebDavTuiLaunch, VoidbError> {
        let fixture_path = matches.get_one::<String>("fixture").cloned();
        let purpose = matches
            .get_one::<String>("purpose")
            .cloned()
            .unwrap_or_else(|| "browser".to_string());
        let readonly = matches.get_flag("readonly");
        let restore = !matches.get_flag("no-restore");

        if let Some(profile_ref) = matches.get_one::<String>("profile") {
            let (profile, connection) =
                ctx.resolve_profile_connection(profile_ref, Some("webdav"))?;
            let config = connection
                .plugin_config
                .as_ref()
                .ok_or_else(|| VoidbError::Connection("Missing plugin_config".to_string()))
                .and_then(|pc| {
                    serde_json::from_value(pc.clone()).map_err(|e| {
                        VoidbError::Connection(format!("Invalid WebDAV config: {}", e))
                    })
                })?;
            let profile_arg = profile_ref_arg(profile_ref, &profile.id);
            let request = TuiLaunchRequest::new("webdav", profile_arg, purpose.clone())
                .readonly(readonly)
                .restore(restore)
                .raw_input(false);
            let launch_plan = build_tui_launch_plan(&profile, request, "voidb-cli", Utc::now())?;

            return Ok(WebDavTuiLaunch {
                profile_label: profile.name,
                config: Some(config),
                source: WebDavTuiSource::Profile,
                fixture_path,
                purpose,
                readonly,
                restore,
                launch_plan: Some(launch_plan),
            });
        }

        if let Some(conn_name) = matches.get_one::<String>("connection") {
            return Ok(WebDavTuiLaunch {
                profile_label: conn_name.clone(),
                config: Some(Self::parse_config(conn_name, ctx)?),
                source: WebDavTuiSource::Connection,
                fixture_path,
                purpose,
                readonly,
                restore,
                launch_plan: None,
            });
        }

        if fixture_path.is_some() {
            return Ok(WebDavTuiLaunch {
                profile_label: "fixture".to_string(),
                config: None,
                source: WebDavTuiSource::Fixture,
                fixture_path,
                purpose,
                readonly,
                restore,
                launch_plan: None,
            });
        }

        Err(VoidbError::Plugin(
            "webdav tui requires --profile, --connection, or --fixture".to_string(),
        ))
    }

    async fn handle_tui(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let launch = Self::parse_tui_launch(matches, ctx)?;
        if let Some(path) = matches.get_one::<String>("evidence") {
            let evidence = build_webdav_tui_evidence(&launch)
                .map_err(|e| VoidbError::Plugin(format!("WebDAV TUI evidence failed: {}", e)))?;
            let rendered = serde_json::to_string_pretty(&evidence).map_err(|e| {
                VoidbError::Plugin(format!("WebDAV TUI evidence serialization failed: {}", e))
            })?;
            if let Some(parent) = std::path::Path::new(path).parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|e| {
                    VoidbError::Plugin(format!(
                        "Failed to create WebDAV TUI evidence directory '{}': {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            fs::write(path, rendered).map_err(|e| {
                VoidbError::Plugin(format!(
                    "Failed to write WebDAV TUI evidence '{}': {}",
                    path, e
                ))
            })?;
            println!("Wrote WebDAV TUI evidence to {path}");
            return Ok(());
        }

        if matches
            .get_one::<String>("format")
            .is_some_and(|format| format == "json")
        {
            write_webdav_tui_preflight(&launch)
                .map_err(|e| VoidbError::Plugin(format!("WebDAV TUI preflight failed: {}", e)))?;
            return Ok(());
        }

        run_webdav_tui(launch)
            .await
            .map_err(|e| VoidbError::Plugin(format!("WebDAV TUI failed: {}", e)))
    }

    async fn handle_ls(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let path = matches.get_one::<String>("path").unwrap();

        let entries = svc
            .list_dir(path)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;

        for entry in &entries {
            let type_indicator = match entry.entry_type {
                crate::types::DavEntryType::Directory => "[DIR] ",
                crate::types::DavEntryType::File => "      ",
            };
            let size_str = match entry.entry_type {
                crate::types::DavEntryType::Directory => String::from("-"),
                crate::types::DavEntryType::File => format_size(entry.size),
            };
            let modified = entry.last_modified.as_deref().unwrap_or("-");
            println!(
                "{}{:<40} {:>10}  {}",
                type_indicator, entry.name, size_str, modified
            );
        }
        eprintln!("({} entries)", entries.len());
        Ok(())
    }

    async fn handle_get(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let remote = matches.get_one::<String>("remote").unwrap();
        let local = matches.get_one::<String>("local").unwrap();
        if std::path::Path::new(local).exists() && !matches.get_flag("overwrite") {
            return Err(VoidbError::Plugin(
                "Local destination exists; pass --overwrite to authorize replacement.".to_string(),
            ));
        }

        let total = svc
            .get_properties(remote)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?
            .size;
        let data = await_transfer(matches, AgentTransferOperation::Download, total, async {
            let data = svc
                .download(remote)
                .await
                .map_err(|e| VoidbError::Plugin(e.to_string()))?;
            std::fs::write(local, &data)
                .map_err(|e| VoidbError::Plugin(format!("Failed to write local file: {e}")))?;
            Ok(data)
        })
        .await?;

        if transfer_output_format(matches) == TransferOutputFormat::Human {
            println!(
                "Downloaded: {} -> {} ({})",
                remote,
                local,
                format_size(data.len() as u64)
            );
        }
        Ok(())
    }

    async fn handle_put(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let local = matches.get_one::<String>("local").unwrap();
        let remote = matches.get_one::<String>("remote").unwrap();
        if svc
            .resource_exists(remote)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?
            && !matches.get_flag("overwrite")
        {
            return Err(VoidbError::Plugin(
                "Remote destination exists; pass --overwrite to authorize replacement.".to_string(),
            ));
        }

        let data = std::fs::read(local)
            .map_err(|e| VoidbError::Plugin(format!("Failed to read local file: {}", e)))?;

        let size = data.len() as u64;
        await_transfer(matches, AgentTransferOperation::Upload, size, async {
            svc.upload(remote, data)
                .await
                .map_err(|e| VoidbError::Plugin(e.to_string()))
        })
        .await?;

        if transfer_output_format(matches) == TransferOutputFormat::Human {
            println!("Uploaded: {} -> {} ({})", local, remote, format_size(size));
        }
        Ok(())
    }

    async fn handle_mkdir(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let path = matches.get_one::<String>("path").unwrap();

        svc.mkdir(path)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;

        println!("Created directory: {}", path);
        Ok(())
    }

    async fn handle_rm(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let path = matches.get_one::<String>("path").unwrap();

        svc.delete(path)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;

        println!("Deleted: {}", path);
        Ok(())
    }

    async fn handle_mv(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let from = matches.get_one::<String>("from").unwrap();
        let to = matches.get_one::<String>("to").unwrap();

        let total = svc
            .get_properties(from)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?
            .size;
        let options = copy_move_options(matches)?;
        await_transfer(matches, AgentTransferOperation::Move, total, async {
            svc.move_item_with_options(from, to, &options)
                .await
                .map_err(|e| VoidbError::Plugin(e.to_string()))
        })
        .await?;

        if transfer_output_format(matches) == TransferOutputFormat::Human {
            println!("Moved: {} -> {}", from, to);
        }
        Ok(())
    }

    async fn handle_cp(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let from = matches.get_one::<String>("from").unwrap();
        let to = matches.get_one::<String>("to").unwrap();

        let total = svc
            .get_properties(from)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?
            .size;
        let options = copy_move_options(matches)?;
        await_transfer(matches, AgentTransferOperation::Copy, total, async {
            svc.copy_item_with_options(from, to, &options)
                .await
                .map_err(|e| VoidbError::Plugin(e.to_string()))
        })
        .await?;

        if transfer_output_format(matches) == TransferOutputFormat::Human {
            println!("Copied: {} -> {}", from, to);
        }
        Ok(())
    }

    async fn handle_info(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let path = matches.get_one::<String>("path").unwrap();

        let entry = svc
            .get_properties(path)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;

        println!("Name:         {}", entry.name);
        println!("Href:         {}", entry.href);
        println!(
            "Type:         {}",
            match entry.entry_type {
                crate::types::DavEntryType::File => "File",
                crate::types::DavEntryType::Directory => "Directory",
            }
        );
        println!("Size:         {}", format_size(entry.size));
        println!(
            "Modified:     {}",
            entry.last_modified.as_deref().unwrap_or("-")
        );
        println!(
            "Content-Type: {}",
            entry.content_type.as_deref().unwrap_or("-")
        );
        println!("ETag:         {}", entry.etag.as_deref().unwrap_or("-"));
        Ok(())
    }

    async fn handle_test(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let config = Self::get_config(matches, ctx)?;
        let svc =
            WebDavService::new_direct(&config).map_err(|e| VoidbError::Plugin(e.to_string()))?;

        let entries = svc
            .list_dir("/")
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;

        println!("Connection successful!");
        println!("Server: {}", config.url);
        println!("Root contains {} entries", entries.len());
        Ok(())
    }

    async fn handle_sync(
        &self,
        mode: SyncMode,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let svc = Self::connect(matches, ctx)?;
        let remote = matches.get_one::<String>("remote").unwrap();
        let local = matches.get_one::<String>("local").unwrap();
        let dry_run = matches.get_flag("dry-run");
        let delete = matches.get_flag("delete");
        let exclude: Vec<String> = matches
            .get_many::<String>("exclude")
            .map(|vals| vals.cloned().collect())
            .unwrap_or_default();

        let options = SyncOptions {
            mode,
            delete_extra: delete,
            dry_run,
            exclude,
        };

        eprintln!("Scanning remote: {}...", remote);
        let remote_entries = svc
            .walk_remote_tree(remote)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;
        eprintln!("Found {} remote entries", remote_entries.len());

        eprintln!("Scanning local: {}...", local);
        let local_entries =
            WebDavService::walk_local_tree(local).map_err(|e| VoidbError::Plugin(e.to_string()))?;
        eprintln!("Found {} local entries", local_entries.len());

        let plan = WebDavService::compute_sync_plan(&remote_entries, &local_entries, &options);
        println!("{}", WebDavService::format_sync_plan(&plan));

        if dry_run {
            println!("(dry run - no changes made)");
            return Ok(());
        }

        if plan.changes.is_empty() {
            return Ok(());
        }

        let result = svc
            .execute_sync(&plan, remote, local)
            .await
            .map_err(|e| VoidbError::Plugin(e.to_string()))?;

        println!(
            "Sync complete: {} downloaded, {} uploaded, {} deleted",
            result.downloaded, result.uploaded, result.deleted
        );
        Ok(())
    }
}

fn overwrite_arg() -> Arg {
    Arg::new("overwrite")
        .long("overwrite")
        .action(ArgAction::SetTrue)
        .help("Explicitly authorize replacement of an existing destination")
}

fn copy_move_args() -> Vec<Arg> {
    vec![
        overwrite_arg(),
        Arg::new("depth")
            .long("depth")
            .value_parser(["0", "infinity"])
            .default_value("0")
            .help("WebDAV COPY/MOVE depth"),
        Arg::new("if-match")
            .long("if-match")
            .value_name("ETAG")
            .conflicts_with("if-none-match")
            .help("Require the source ETag to match"),
        Arg::new("if-none-match")
            .long("if-none-match")
            .action(ArgAction::SetTrue)
            .help("Require the destination not to exist"),
    ]
}

fn copy_move_options(
    matches: &ArgMatches,
) -> Result<crate::types::WebDavCopyMoveOptions, VoidbError> {
    Ok(crate::types::WebDavCopyMoveOptions {
        overwrite: matches.get_flag("overwrite"),
        depth_infinity: matches
            .get_one::<String>("depth")
            .is_some_and(|depth| depth == "infinity"),
        if_match: matches.get_one::<String>("if-match").cloned(),
        if_none_match: matches.get_flag("if-none-match"),
        lock_token: None,
    })
}

fn transfer_format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_parser(["human", "json", "ndjson"])
        .default_value("human")
        .help("Transfer progress output format")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferOutputFormat {
    Human,
    Json,
    Ndjson,
}

fn transfer_output_format(matches: &ArgMatches) -> TransferOutputFormat {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") => TransferOutputFormat::Json,
        Some("ndjson") => TransferOutputFormat::Ndjson,
        _ => TransferOutputFormat::Human,
    }
}

async fn await_transfer<T>(
    matches: &ArgMatches,
    operation: AgentTransferOperation,
    total: u64,
    future: impl Future<Output = Result<T, VoidbError>>,
) -> Result<T, VoidbError> {
    let transfer_id = format!(
        "webdav-cli-{}-{}",
        operation.as_str(),
        Utc::now().timestamp_micros()
    );
    emit_transfer_event(
        matches,
        &AgentTransferEvent::single_object_snapshot(
            &transfer_id,
            operation,
            AgentTransferPhase::Transferring,
            1,
            0,
            Some(total),
        ),
    )?;
    tokio::select! {
        result = future => match result {
            Ok(value) => {
                emit_transfer_event(
                    matches,
                    &AgentTransferEvent::single_object_snapshot(
                        transfer_id,
                        operation,
                        AgentTransferPhase::Completed,
                        2,
                        total,
                        Some(total),
                    ),
                )?;
                Ok(value)
            }
            Err(failure) => {
                emit_transfer_event(
                    matches,
                    &AgentTransferEvent::single_object_snapshot(
                        transfer_id,
                        operation,
                        AgentTransferPhase::Failed,
                        2,
                        0,
                        Some(total),
                    ),
                )?;
                Err(failure)
            }
        },
        _ = tokio::signal::ctrl_c() => {
            emit_transfer_event(
                matches,
                &AgentTransferEvent::single_object_snapshot(
                    &transfer_id,
                    operation,
                    AgentTransferPhase::Cancelling,
                    2,
                    0,
                    Some(total),
                ),
            )?;
            emit_transfer_event(
                matches,
                &AgentTransferEvent::single_object_snapshot(
                    transfer_id,
                    operation,
                    AgentTransferPhase::Cancelled,
                    3,
                    0,
                    Some(total),
                ),
            )?;
            Err(VoidbError::Plugin(
                "WebDAV transfer cancelled; remote state was not assumed clean.".to_string(),
            ))
        }
    }
}

fn emit_transfer_event(matches: &ArgMatches, event: &AgentTransferEvent) -> Result<(), VoidbError> {
    match transfer_output_format(matches) {
        TransferOutputFormat::Human => {
            if event.phase != AgentTransferPhase::Completed {
                eprintln!("{}", event.human_summary());
            }
        }
        TransferOutputFormat::Json if event.terminal => {
            println!(
                "{}",
                serde_json::to_string_pretty(event).map_err(|error| {
                    VoidbError::Plugin(format!("Failed to serialize transfer event: {error}"))
                })?
            );
        }
        TransferOutputFormat::Json => {}
        TransferOutputFormat::Ndjson => {
            println!(
                "{}",
                serde_json::to_string(event).map_err(|error| {
                    VoidbError::Plugin(format!("Failed to serialize transfer event: {error}"))
                })?
            );
        }
    }
    Ok(())
}

/// Format file size in human-readable form
fn format_size(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < units.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, units[0])
    } else {
        format!("{:.1} {}", size, units[unit_idx])
    }
}

fn profile_ref_arg(input: &str, resolved_profile_id: &str) -> ConnectionProfileRef {
    if let Some(id) = input.strip_prefix("id:") {
        ConnectionProfileRef::Id(id.to_string())
    } else if let Some(name) = input
        .strip_prefix("name:")
        .or_else(|| input.strip_prefix("alias:"))
    {
        ConnectionProfileRef::Name(name.to_string())
    } else if input == resolved_profile_id {
        ConnectionProfileRef::Id(input.to_string())
    } else {
        ConnectionProfileRef::Name(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_commands_expose_structured_output_and_preconditions() {
        let command = WebDavCliPlugin
            .commands()
            .into_iter()
            .find(|command| command.get_name() == "cp")
            .unwrap();
        let matches = command
            .try_get_matches_from([
                "cp",
                "--connection",
                "fixture",
                "/source/a",
                "/destination/b",
                "--overwrite",
                "--depth",
                "infinity",
                "--if-match",
                "\"etag\"",
                "--format",
                "ndjson",
            ])
            .expect("WebDAV transfer CLI arguments");
        assert!(matches.get_flag("overwrite"));
        assert_eq!(
            matches.get_one::<String>("depth").map(String::as_str),
            Some("infinity")
        );
        assert_eq!(
            transfer_output_format(&matches),
            TransferOutputFormat::Ndjson
        );
    }
}
