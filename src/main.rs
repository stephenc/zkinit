// Copyright 2019 Stephen Connolly.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE.txt or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT.txt or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate getopts;
extern crate zookeeper;

use std::env;
use std::fs::File;
use std::io::Read;
use std::time::Duration;

use getopts::Options;
use zookeeper::{Acl, CreateMode, WatchedEvent, Watcher, ZkError, ZooKeeper};

fn create_options() -> Options {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu and exit");
    opts.optflag("V", "version", "print the version and exit");
    opts.optflag("u", "update", "update the path if it exists already");
    opts.optflag("d", "debug", "output connection state information");
    opts.optflag("p", "parents", "ensure all parent nodes exist prior to attempting to create the node");
    opts.optflag("c", "create-required", "fail if the node already exists in ZooKeeper");
    opts.optopt("z", "zookeeper", "zookeeper quorum hosts to connect to (if not specified then the ZK_HOSTS environment variable will be used)", "ZK_HOSTS");
    opts.optopt("", "auth-digest", "use digest authentication", "DIGEST");
    opts
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] /path/to/zookeeper/node [file]", program);
    println!("{}", opts.usage(&brief));
    println!();
    println!("Creates a node in zookeeper with content from a specific file (or empty content");
    println!("if no file specified)");
    println!();
}

struct LoggingWatcher;

impl Watcher for LoggingWatcher {
    fn handle(&self, e: WatchedEvent) {
        eprintln!("{:?}", e)
    }
}

fn main() {
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let opts = create_options();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    let zk_node :Option<&String> = matches.free.get(0);
    if zk_node.is_none() || matches.free.len() > 2 {
        print_usage(&program, opts);
        std::process::exit(2)
    }
    let zk_node = zk_node.unwrap();
    if matches.opt_present("V") {
        println!("{}", VERSION);
        return;
    }
    let zk_hosts = match matches.opt_str("z").or(match env::var("ZK_HOSTS") {
        Ok(v) => Some(v),
        Err(_) => None
    }) {
        Some(v) => v,
        None => {
            eprintln!("You must specify the zookeeper quorum to connect to, either using the");
            eprintln!("--zookeeper command line option or the ZK_HOSTS environment variable");
            std::process::exit(2)
        }
    };

    if zk_node.chars().next().unwrap() != '/' {
        eprintln!("The node must start with a / character");
        std::process::exit(2)
    }

    if zk_node.chars().rev().next().unwrap() == '/' {
        eprintln!("The node must not end with a / character");
        std::process::exit(2)
    }



    let zk = ZooKeeper::connect(&*zk_hosts, Duration::from_secs(15), LoggingWatcher).unwrap();

    match match matches.opt_str("auth-digest") {
        Some(secret) => zk.add_auth("digest", Vec::from(secret.as_bytes())),
        None => Ok(())
    } {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Could not authenticate: {:?}", e);
            std::process::exit(6)
        }
    }

    if matches.opt_present("d") {
        zk.add_listener(|zk_state| eprintln!("[DEBUG] ZooKeeper state {:?}", zk_state));
    }

    let mut data = Vec::new();

    let fail_if_exists = matches.opt_present("c");
    let update_if_exists = matches.opt_present("u");
    match matches.free.get(1) {
        Some(data_file) => {
            let mut file = match File::open(data_file) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Could not open {}: {:?}", data_file, e);
                    std::process::exit(1)
                }
            };

            match file.read_to_end(&mut data) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Could not read {}: {:?}", data_file, e);
                    std::process::exit(1)
                }
            }
        }
        None => ()
    }


    if matches.opt_present("p") {
         for (index,_) in zk_node.match_indices('/').skip(1) {
             let zk_parent : String = zk_node.chars().take(index).collect();
             match zk.create(zk_parent.as_str(), Vec::new(), Acl::open_unsafe().clone(), CreateMode::Persistent) {
                 Ok(_) => (),
                 Err(e) => {
                     match e {
                         ZkError::NodeExists => (),  // expected
                         ZkError::NoNode => {
                             eprintln!("Parent node for {} does not exist. This should never happen", zk_parent);
                             std::process::exit(99)
                         }
                         _ => {
                             eprintln!("Could not create node {} : {:?}", zk_parent, e);
                             std::process::exit(99)
                         }
                     }
                 }
             }
         }
    }

    match zk.create(zk_node.as_str(), data.clone(), Acl::open_unsafe().clone(), CreateMode::Persistent) {
        Ok(_) => (),
        Err(e) => {
            match e {
                ZkError::NodeExists => {
                    if fail_if_exists {
                        eprintln!("Node {} exists", zk_node);
                        std::process::exit(3)
                    }
                    if update_if_exists {
                        match zk.set_data(zk_node.as_str(), data, None) {
                            Ok(_) => (),
                            Err(e) => {
                                eprintln!("Could not update {}: {:?}", zk_node, e);
                                std::process::exit(4)
                            }
                        }
                    }
                },
                ZkError::NoNode => {
                    eprintln!("Parent node for {} does not exist, consider using --parents command line option", zk_node);
                    std::process::exit(5)
                }
                _ => {
                    eprintln!("Could not create node {} : {:?}", zk_node, e);
                    std::process::exit(99)
                }
            }
        }
    }
}
