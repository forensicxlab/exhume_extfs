mod extfs;

use clap::{Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_body::Body;
use extfs::ExtFS;

fn process_extfs(body: &mut Body, offset: &usize, verbose: &bool) {
    let filesystem = match ExtFS::new(body, offset) {
        Ok(fs) => Some(fs),
        Err(message) => {
            eprintln!("ExtFS object creation error: {:?}", message);
            None
        }
    };

    if let Some(fs) = &filesystem {
        if *verbose {
            println!("ExtFS created successfully.");
        }
        fs.print_info();
    }
}

fn process_partition(file_path: &str, format: &str, fstype: &str, offset: &usize, verbose: &bool) {
    let mut body = Body::new(file_path.to_string(), format);
    if *verbose {
        body.print_info();
    }

    match fstype {
        "extfs" => {
            if *verbose {
                println!("Parsing the partition as the Extended File System format");
            }
            process_extfs(&mut body, offset, verbose);
        }
        _ => {
            eprintln!("The filesystem type to parse isn't supported. Supported formats is 'extfs'")
        }
    }
}

fn main() {
    let matches = Command::new("exhume_metadata")
        .version("1.0")
        .author("ForensicXlab")
        .about("Exhume the metadata from a given partition.")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The path to the input file."),
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
                .help("Extract the metadata for the partition at the start address X"),
        )
        .arg(
            Arg::new("fstype")
                .short('t')
                .long("fstype")
                .value_parser(clap::value_parser!(String))
                .required(true)
                .help("The filesystem type. Currently supported: extfs"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("input").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let fstype = matches.get_one::<String>("fstype").unwrap();
    let offset = matches.get_one::<usize>("offset").unwrap();
    let verbose = match matches.get_one::<bool>("verbose") {
        Some(verbose) => verbose,
        None => &false,
    };
    process_partition(file_path, format, fstype, offset, verbose);
}
