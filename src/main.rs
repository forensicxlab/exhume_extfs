mod extfs;

use clap::{value_parser, Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_body::Body;
use extfs::ExtFS;
use log::{debug, error, info};

fn process_partition(
    file_path: &str,
    format: &str,
    offset: &u64,
    superblock: &bool,
    inode_number: &usize,
    groupdesc: &bool,
    json: &bool,
) {
    let mut body = Body::new_from(file_path.to_string(), format, Some(*offset));
    // Log body creation at debug level.
    debug!("Created Body from '{}'", file_path);

    let mut filesystem = match ExtFS::new(&mut body, *offset) {
        Ok(fs) => Some(fs),
        Err(message) => {
            error!("ExtFS object creation error: {}", message);
            None
        }
    };

    if let Some(fs) = &mut filesystem {
        info!("ExtFS created successfully.");
        if *superblock {
            fs.superblock.print_sp_info();
        }

        if *inode_number > 0 {
            if let Err(err) = fs.load_group_descriptors() {
                error!("{}", err);
            }
            let inode = match fs.get_inode(*inode_number as u32) {
                Ok(inode) => inode,
                Err(err) => {
                    error!("{}", err);
                    std::process::exit(1);
                }
            };

            // let file = match fs.read_file("/abi-3.13.0-24-generic") {
            //     Ok(file) => file,
            //     Err(err) => {
            //         error!("{}", err);
            //         std::process::exit(1);
            //     }
            // };
            // info!("File read: {:?}", file);
            if *json {
                match serde_json::to_string_pretty(&inode.to_json()) {
                    Ok(json_str) => info!("{}", json_str),
                    Err(e) => error!("Error serializing inode: {}", e),
                }
            } else {
                info!("Display the prettytable here");
            }

            // let test = match fs.read(*inode_number as u32) {
            //     Ok(test) => test,
            //     Err(err) => {
            //         eprintln!("{}", err);
            //         std::process::exit(1);
            //     }
            // };
            // println!("{:?}", String::from_utf8_lossy(&test));
        }

        if *groupdesc {
            if let Err(err) = fs.load_group_descriptors() {
                error!("{}", err);
                std::process::exit(1);
            } else {
                if *json {
                    if let Ok(bg_descriptors) = fs.get_bg_descriptors() {
                        let json_array: Vec<_> =
                            bg_descriptors.iter().map(|gd| gd.to_json()).collect();
                        match serde_json::to_string_pretty(&json_array) {
                            Ok(json_str) => info!("{}", json_str),
                            Err(e) => error!("Error serializing group descriptors: {}", e),
                        }
                    }
                } else {
                    info!("Display the prettytable here");
                }
            }
        }
    }
}

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
                .help("The extfs partition starts at address 0x...."),
        )
        .arg(
            Arg::new("inode")
                .short('i')
                .long("inode")
                .value_parser(maybe_hex::<usize>)
                .required(false)
                .help("Get the metadata about a specific inode number (must be >= 2)."),
        )
        .arg(
            Arg::new("superblock")
                .short('s')
                .long("superblock")
                .action(ArgAction::SetTrue)
                .help("Display the superblock information."),
        )
        .arg(
            Arg::new("groupdesc")
                .short('g')
                .long("groupdesc")
                .action(ArgAction::SetTrue)
                .help("Display the group descriptors"),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue),
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
    let superblock = matches.get_one::<bool>("superblock").unwrap_or(&false);
    let groupdesc = matches.get_one::<bool>("groupdesc").unwrap_or(&false);
    let inode = matches.get_one::<usize>("inode").unwrap_or(&0usize);
    let json = matches.get_one::<bool>("json").unwrap_or(&false);

    process_partition(
        file_path, format, offset, superblock, inode, groupdesc, json,
    );
}
