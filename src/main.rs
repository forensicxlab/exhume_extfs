mod extfs;

use clap::{Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_body::Body;
use extfs::ExtFS;
use std::io::Read;

fn process_partition(
    file_path: &str,
    format: &str,
    offset: &u64,
    superblock: &bool,
    inode_number: &usize,
    groupdesc: &bool,
    json: &bool,
    verbose: &bool,
) {
    let mut body = Body::new_from(file_path.to_string(), format, Some(*offset));
    if *verbose {
        body.print_info();
    }

    // let lvm = Lvm2::open(&mut body, *offset).unwrap();
    // let lv = lvm.lvs().next().unwrap();
    // println!("LV {}", lv.name());
    // println!("{:?}", lv.raw_metadata());
    // let mut olv = lvm.open_lv(lv, &mut body);

    // let mut buf = [0u8; 1024];
    // olv.read_exact(&mut buf).unwrap();
    // for _ in 0..16 {
    //     let mut buf2 = [0u8; 16];
    //     olv.read_exact(&mut buf2).unwrap();
    //     println!("{buf2:x?}");
    // }

    let mut filesystem = match ExtFS::new(&mut body, *offset) {
        Ok(fs) => Some(fs),
        Err(message) => {
            eprintln!("ExtFS object creation error: {}", message);
            None
        }
    };

    if let Some(fs) = &mut filesystem {
        if *verbose {
            println!("ExtFS created successfully.");
        }
        if *superblock {
            fs.superblock.print_sp_info();
        }

        if *inode_number > 0 {
            match fs.load_group_descriptors() {
                Ok(_) => {}
                Err(err) => eprintln!("{}", err),
            };
            let inode = match fs.get_inode(*inode_number as u32) {
                Ok(inode) => inode,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };

            // let test = match fs.read(*inode_number as u32) {
            //     Ok(test) => test,
            //     Err(err) => {
            //         eprintln!("{}", err);
            //         std::process::exit(1);
            //     }
            // };
            // println!("{:?}", String::from_utf8_lossy(&test));

            let file = match fs.read_file("/abi-3.13.0-24-generic") {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            println!("{:?}", file);
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&inode.to_json()).unwrap()
                );
            } else {
                println!("Display the prettytable here");
            }
        }

        if *groupdesc {
            match fs.load_group_descriptors() {
                Ok(_) => {
                    if *json {
                        let json_array: Vec<_> = fs
                            .get_bg_descriptors()
                            .unwrap()
                            .iter()
                            .map(|group_descriptor| group_descriptor.to_json())
                            .collect();

                        println!("{}", serde_json::to_string_pretty(&json_array).unwrap());
                    } else {
                        println!("Display the prettytable here");
                    }
                }
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
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
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("body").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let offset = matches.get_one::<u64>("offset").unwrap();
    let verbose = match matches.get_one::<bool>("verbose") {
        Some(verbose) => verbose,
        None => &false,
    };
    let superblock = match matches.get_one::<bool>("superblock") {
        Some(superblock) => superblock,
        None => &false,
    };
    let groupdesc = match matches.get_one::<bool>("groupdesc") {
        Some(groupdesc) => groupdesc,
        None => &false,
    };
    let inode = match matches.get_one::<usize>("inode") {
        Some(inode) => inode,
        None => &0usize,
    };
    let json = match matches.get_one::<bool>("json") {
        Some(json) => json,
        None => &false,
    };

    process_partition(
        file_path, format, offset, superblock, inode, groupdesc, json, verbose,
    );
}
