mod extfs;

use clap::{Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_body::Body;
use extfs::ExtFS;

fn process_partition(
    file_path: &str,
    format: &str,
    offset: &usize,
    superblock: &bool,
    inode_number: &usize,
    verbose: &bool,
) {
    let mut body = Body::new(file_path.to_string(), format);
    if *verbose {
        body.print_info();
    }

    let mut filesystem = match ExtFS::new(&mut body, offset) {
        Ok(fs) => Some(fs),
        Err(message) => {
            eprintln!("ExtFS object creation error: {:?}", message);
            None
        }
    };

    if let Some(fs) = &mut filesystem {
        if *verbose {
            println!("ExtFS created successfully.");
        }
        if *superblock {
            fs.print_superblock_metadata();
        }

        if *inode_number > 0 {
            fs.build_system_tree();
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
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The format of the file, either 'raw' or 'ewf'."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<usize>)
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
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("body").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let offset = matches.get_one::<usize>("offset").unwrap();
    let verbose = match matches.get_one::<bool>("verbose") {
        Some(verbose) => verbose,
        None => &false,
    };
    let superblock = match matches.get_one::<bool>("superblock") {
        Some(superblock) => superblock,
        None => &false,
    };
    let inode = match matches.get_one::<usize>("inode") {
        Some(inode) => inode,
        None => &0usize,
    };

    process_partition(file_path, format, offset, superblock, inode, verbose);
}
