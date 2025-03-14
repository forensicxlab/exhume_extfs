use clap::{value_parser, Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_body::{Body, BodySlice};
use log::{debug, error, info};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;

mod extfs;
use extfs::ExtFS;

fn main() {
    let matches = Command::new("exhume_extfs")
        .version("1.0")
        .author("ForensicXlab")
        .about("Exhume the metadata from an extfs partition.")
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
                .required(true)
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
                .long("inode")
                .value_parser(maybe_hex::<usize>)
                .help("Display the metadata about a specific inode number (>=2)."),
        )
        .arg(
            Arg::new("dir_entry")
                .long("dir_entry")
                .action(ArgAction::SetTrue)
                .help("If --inode is specified and it is a directory, list its directory entries."),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
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
            Arg::new("groupdesc")
                .long("groupdesc")
                .action(ArgAction::SetTrue)
                .help("Display group descriptors (placeholder)."),
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
    let format = matches.get_one::<String>("format").unwrap();
    let offset = matches.get_one::<u64>("offset").unwrap();
    let size = matches.get_one::<u64>("size").unwrap();

    let show_superblock = matches.get_flag("superblock");
    let show_groupdesc = matches.get_flag("groupdesc");
    let inode_num = matches.get_one::<usize>("inode").copied().unwrap_or(0);
    let show_dir_entry = matches.get_flag("dir_entry");
    let dump_content = matches.get_flag("dump");
    let json_output = matches.get_flag("json");

    // 1) Prepare the "body" and create an ExtFS instance.
    let mut body = Body::new(file_path.to_owned(), format);
    debug!("Created Body from '{}'", file_path);

    let partition_size = *size * body.get_sector_size() as u64;
    let mut slice = match BodySlice::new(&mut body, *offset, partition_size) {
        Ok(sl) => sl,
        Err(e) => {
            error!("Could not create BodySlice: {}", e);
            std::process::exit(1);
        }
    };

    let mut filesystem = match ExtFS::new(&mut slice) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Couldn't open ExtFS: {}", e);
            std::process::exit(1);
        }
    };

    // 2) --superblock
    if show_superblock {
        if json_output {
            match serde_json::to_string_pretty(&filesystem.superblock.to_json()) {
                Ok(s) => println!("{}", s),
                Err(e) => error!("Error serializing superblock to JSON: {}", e),
            }
        } else {
            filesystem.superblock.print_sp_info();
        }
    }

    // 3) -–groupdesc (placeholder).
    if show_groupdesc {
        info!("--groupdesc is not fully implemented yet.");
        // You could implement loading each GroupDescriptor and printing them,
        // or returning them as JSON if json_output is enabled.
    }

    // 4) --inode [N]
    if inode_num > 0 {
        let inode = match filesystem.get_inode(inode_num as u64) {
            Ok(inode_val) => inode_val,
            Err(e) => {
                error!("Cannot read inode {}: {}", inode_num, e);
                std::process::exit(1);
            }
        };

        // 4a) Display inode metadata
        if json_output {
            match serde_json::to_string_pretty(&inode.to_json()) {
                Ok(json_str) => println!("{}", json_str),
                Err(e) => error!("Error serializing inode {} to JSON: {}", inode_num, e),
            }
        } else {
            // Show a textual summary of its metadata (reusing to_json for brevity):
            let inode_obj = inode.to_json();
            println!("Inode {} metadata:", inode_num);
            println!("{}", inode_obj); // The debug JSON output, or parse fields manually
        }

        // 4b) If --dir_entry is given, try to list directory entries
        if show_dir_entry {
            if inode.is_dir() {
                match filesystem.list_dir(&inode) {
                    Ok(entries) => {
                        if json_output {
                            let arr: Vec<Value> = entries
                                .iter()
                                .map(|de| {
                                    json!({
                                        "inode": de.inode,
                                        "rec_len": de.rec_len,
                                        "file_type": de.file_type,
                                        "name": de.name,
                                    })
                                })
                                .collect();
                            let dir_json = json!({ "dir_entries": arr });
                            println!("{}", serde_json::to_string_pretty(&dir_json).unwrap());
                        } else {
                            println!("Directory listing for inode {}:", inode_num);
                            for de in entries {
                                println!(
                                    "  name='{}', inode={}, type=0x{:x}, rec_len={}",
                                    de.name, de.inode, de.file_type, de.rec_len
                                );
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
        }

        // 4c) If --dump is given, attempt to read content and dump to a file
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
}
