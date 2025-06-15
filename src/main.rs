use clap::{value_parser, Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_body::{Body, BodySlice};
use exhume_extfs::ExtFS;
use log::{debug, error, info};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;

fn main() {
    let matches = Command::new("exhume_extfs")
        .version("0.1.6")
        .author("ForensicXlab")
        .about("Exhume artifacts from an EXTFS partition.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("The format of the file, either 'raw' or 'ewf'."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The extfs partition starts at address (decimal or hex)."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The size of the extfs partition in sectors (decimal or hex)."),
        )
        .arg(
            Arg::new("inode")
                .short('i')
                .long("inode")
                .value_parser(maybe_hex::<usize>)
                .help("Display the metadata about a specific inode number (>=2)."),
        )
        .arg(
            Arg::new("dir_entry")
                .short('d')
                .long("dir_entry")
                .requires("inode")
                .action(ArgAction::SetTrue)
                .help("If --inode is specified and it is a directory, list its directory entries."),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .requires("inode")
                .action(ArgAction::SetTrue)
                .help("If --inode is specified, dump its content to a file named 'inode_<N>.bin'."),
        )
        .arg(
            Arg::new("superblock")
                .long("superblock")
                .action(ArgAction::SetTrue)
                .help("Display the superblock information."),
        )
        .arg(
            Arg::new("journal")
                .long("journal")
                .action(ArgAction::SetTrue)
                .help("Display the journal block listing (jls)."),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output certain structures (superblock, inode) in JSON format."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level"),
        )
        .arg(
            Arg::new("recover")
                .long("recover")
                .action(ArgAction::SetTrue)
                .help("Scan all free inodes and carve deleted files"),
        )
        .arg(
            Arg::new("timeline")
                .long("timeline")
                .short('t')
                .requires("journal")
                .action(ArgAction::SetTrue)
                .help("Print a JSON timeline assembled from the ext4 journal"),
        )
        .get_matches();

    // Initialize logger.
    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    let file_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let offset = matches.get_one::<u64>("offset").unwrap();
    let size = matches.get_one::<u64>("size").unwrap();

    let show_superblock = matches.get_flag("superblock");
    let journal = matches.get_flag("journal");
    let inode_num = matches.get_one::<usize>("inode").copied().unwrap_or(0);
    let show_dir_entry = matches.get_flag("dir_entry");
    let dump_content = matches.get_flag("dump");
    let json_output = matches.get_flag("json");
    let recover_deleted = matches.get_flag("recover");

    // 1) Prepare the "body" and create an ExtFS instance.
    let mut body = Body::new(file_path.to_owned(), format);
    debug!("Created Body from '{}'", file_path);

    let partition_size = *size * body.get_sector_size() as u64;
    let mut slice = match BodySlice::new(&mut body, *offset, partition_size) {
        Ok(sl) => sl,
        Err(e) => {
            error!("Could not create BodySlice: {}", e);
            return;
        }
    };

    let mut filesystem = match ExtFS::new(&mut slice) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Couldn't open ExtFS: {}", e);
            return;
        }
    };

    if show_superblock {
        if json_output {
            match serde_json::to_string_pretty(&filesystem.superblock.to_json()) {
                Ok(s) => println!("{}", s),
                Err(e) => error!("Error serializing superblock to JSON: {}", e),
            }
        } else {
            println!("{}", filesystem.superblock.to_string());
        }
    }

    if journal {
        if matches.get_flag("timeline") {
            match filesystem.build_timeline() {
                Ok(tl) => {
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&tl).unwrap());
                    } else {
                        for ev in tl {
                            let extra = match ev.action.as_str() {
                                "chmod" => format!(
                                    " {} → {}",
                                    ev.details.get("old_sym").unwrap(),
                                    ev.details.get("new_sym").unwrap()
                                ),
                                _ => String::new(),
                            };
                            println!("{}  Tx-{}  {} {}", ev.ts, ev.tx_seq, ev.action, ev.target);
                            if !extra.is_empty() {
                                println!("            {}", extra);
                            }
                        }
                    }
                }
                Err(e) => error!("Timeline build failed: {}", e),
            }
        } else {
            match filesystem.read_journal_bytes() {
                Ok(jbytes) => {
                    for entry in exhume_extfs::list_journal_blocks(&jbytes) {
                        println!(
                            "{:<6}:  {}",
                            entry.index,
                            entry.description.replace('\n', "\n        ")
                        );
                    }
                }
                Err(e) => error!("Could not read journal: {}", e),
            }
        }
    }

    if inode_num > 0 {
        let inode = match filesystem.get_inode(inode_num as u64) {
            Ok(inode_val) => inode_val,
            Err(e) => {
                error!("Cannot read inode {}: {}", inode_num, e);
                return;
            }
        };

        if show_dir_entry {
            if inode.is_dir() {
                match filesystem.list_dir(&inode) {
                    Ok(entries) => {
                        if json_output {
                            let arr: Vec<Value> = entries.iter().map(|de| de.to_json()).collect();
                            let dir_json = json!({ "dir_entries": arr });
                            println!("{}", serde_json::to_string_pretty(&dir_json).unwrap());
                        } else {
                            info!("Directory listing for inode {}:", inode_num);
                            for de in entries {
                                println!("{} / 0x{:x} {}", de.inode, de.file_type, de.name);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to list directory for inode {}: {}", inode_num, e);
                    }
                }
            } else {
                error!(
                    "Requested --dir_entry but inode {} is not a directory.",
                    inode_num
                );
            }
        } else {
            if json_output {
                match serde_json::to_string_pretty(&inode.to_json()) {
                    Ok(json_str) => {
                        info!("Inode {} metadata:", inode_num);
                        println!("{}", json_str)
                    }
                    Err(e) => error!("Error serializing inode {} to JSON: {}", inode_num, e),
                }
            } else {
                println!("{}", inode.to_string());
            }
        }

        if dump_content {
            info!(
                "Dumping inode {} content into 'inode_{}.bin'",
                inode_num, inode_num
            );
            match filesystem.read_inode(&inode) {
                Ok(data) => {
                    let filename = format!("inode_{}.bin", inode_num);
                    match File::create(&filename) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(&data) {
                                error!("Error writing file '{}': {}", filename, e);
                            } else {
                                info!(
                                    "Successfully wrote {} bytes into '{}'",
                                    data.len(),
                                    filename
                                );
                            }
                        }
                        Err(e) => error!("Could not create dump file '{}': {}", filename, e),
                    }
                }
                Err(e) => {
                    error!("Cannot read content for inode {}: {}", inode_num, e);
                }
            }
        }
    }

    if recover_deleted {
        info!("Scanning filesystem for deleted files…");
        match filesystem.carve_deleted_files() {
            Ok(recovered) => {
                if json_output {
                    let out: Vec<Value> = recovered
                        .iter()
                        .map(|rf| {
                            json!({
                                "inode":        rf.inode_num,
                                "name":         rf.name,
                                "size":         rf.size,
                                "atime":        rf.atime,
                                "mtime":        rf.mtime,
                                "ctime":        rf.ctime,
                                "deleted_time": rf.deleted_time
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                } else {
                    info!("Recovered {} deleted file(s)", recovered.len());
                    for rf in &recovered {
                        let fname = rf
                            .name
                            .clone()
                            .unwrap_or_else(|| format!("inode_{}.bin", rf.inode_num));
                        println!(
                            "inode {:>6}  {:<30}  ({} bytes)",
                            rf.inode_num, fname, rf.size
                        );
                        if let Err(e) = std::fs::write(&fname, &rf.data) {
                            error!("Could not save '{}': {}", fname, e);
                        }
                    }
                }
            }
            Err(e) => error!("Recovery failed: {}", e),
        }
    }
}
