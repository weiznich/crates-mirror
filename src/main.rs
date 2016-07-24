// Copyright (C) 2016 by Georg Semmler

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(warnings)]
extern crate rustc_serialize;
extern crate router;
extern crate iron;
extern crate curl;
extern crate toml;
extern crate git2;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate sha2;
extern crate clap;

use std::path::PathBuf;
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write, Read, BufReader, BufRead};
use std::sync::{RwLock, Arc};
use std::collections::HashSet;
use std::time::Duration;
use rustc_serialize::Decodable;
use rustc_serialize::json;

use curl::easy::Easy;
use git2::{Repository, ResetType, Cred};
use sha2::{Digest, Sha256};
use clap::{App, Arg};

use iron::prelude::*;
use iron::status::Status;
use iron::modifiers::Redirect;
use iron::Handler;
use iron::Url;
use router::Router;

#[derive(Debug, RustcDecodable, Clone)]
struct GitConfig {
    upstream_url: String,
    origin_url: Option<String>,
}

#[derive(Debug, RustcDecodable, Clone)]
struct Config {
    base_path: String,
    remote_api: String,
    listen_on: String,
    registry_config: GitConfig,
    poll_intervall: Option<i32>,
}

impl Config {
    pub fn from_file(path: &str) -> Config {
        use std::fs::File;
        use std::io::Read;

        let mut config_toml = String::new();

        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => panic!("Could not find config file {}!", path),
        };
        file.read_to_string(&mut config_toml)
            .unwrap_or_else(|err| panic!("Error while reading config: [{}]", err));
        let mut parser = ::toml::Parser::new(&config_toml);
        let toml = parser.parse();

        if toml.is_none() {
            for err in &parser.errors {
                let (loline, locol) = parser.to_linecol(err.lo);
                let (hiline, hicol) = parser.to_linecol(err.hi);
                println!("{}:{}-{}:{} error: {}",
                         loline,
                         locol,
                         hiline,
                         hicol,
                         err.desc);
            }
            panic!("Faild to load Configuration");
        }
        let toml = ::toml::Value::Table(toml.unwrap());

        let mut decoder = ::toml::Decoder::new(toml);
        match Config::decode(&mut decoder) {
            Ok(c) => c,
            Err(e) => panic!("failed to parse configuration {}", e),
        }
    }
}

#[derive(RustcDecodable)]
struct IndexFile {
    vers: String,
    cksum: String,
}

impl IndexFile {
    fn from_line(l: Result<String, ::std::io::Error>) -> IndexFile {
        json::decode(&l.unwrap()).unwrap()
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct Crate {
    name: String,
    version: String,
}


impl Crate {
    fn get_index_file(&self, mut index: PathBuf) -> File {
        match self.name.len() {
            e if e > 3 => {
                index.push(&self.name[0..2]);
                index.push(&self.name[2..4]);
            }
            e => index.push(e.to_string()),
        }
        index.push(self.name.clone());
        File::open(index).unwrap()
    }
}

#[derive(Clone)]
struct Mirror {
    remote_api: String,
    crates_path: PathBuf,
    index_path: PathBuf,
    active_downloads: Arc<RwLock<HashSet<Crate>>>,
}

impl Mirror {
    fn redirect(&self, krate: &Crate) -> IronResult<Response> {
        debug!("redirect to {:?}", krate);
        let url = Url::parse(&format!("{}/api/v1/crates/{}/{}/download",
                                      self.remote_api,
                                      krate.name,
                                      krate.version))
                      .unwrap();
        Ok(Response::with((Status::TemporaryRedirect, Redirect(url))))
    }

    fn download(&self, krate: &Crate) {
        let krate = krate.clone();
        let mirror = self.clone();
        ::std::thread::spawn(move || mirror.fetch(krate, 0));
    }

    fn fetch(self, krate: Crate, retry_count: usize) {
        if retry_count > 20 {
            return;
        }
        debug!("cache crate {:?} for the next request", krate);
        {
            let mut l = self.active_downloads.write().unwrap();
            if l.contains(&krate) {
                return;
            }
            l.insert(krate.clone());
        }
        let mut base_dir = self.crates_path.clone();
        base_dir.push(krate.name.clone());
        base_dir.push(krate.version.clone());
        create_dir_all(base_dir.clone()).unwrap();
        base_dir.push("download");
        let file = File::create(base_dir).unwrap();
        let mut writer = BufWriter::new(file);
        let mut handle = Easy::new();
        let url = format!("{}/api/v1/crates/{}/{}/download",
                        self.remote_api,
                        krate.name,
            krate.version,);
        debug!("try to download {:?} from {}", krate, url);
        handle.url(&url)
              .unwrap();
        handle.follow_location(true).unwrap();
        {
            let mut transfer = handle.transfer();
            transfer.write_function(|data| {
                        debug!("get part of {:?}", krate);
                        Ok(writer.write(data).unwrap())
                    })
                    .unwrap();
            match transfer.perform() {
                Ok(_) => {}
                Err(e) => {
                    warn!("fetch of {:?} failed because {:?}! retry {}",
                          krate,
                          e,
                          retry_count);
                    {
                        let mut l = self.active_downloads.write().unwrap();
                        l.remove(&krate);
                    }
                    self.fetch(krate.clone(), retry_count + 1);
                    return;
                }
            }
        }
        {
            let mut l = self.active_downloads.write().unwrap();
            l.remove(&krate);
        }
        debug!("finish fetch {:?}", krate);
    }
}



impl Handler for Mirror {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let crate_name = req.extensions
                            .get::<Router>()
                            .unwrap()
                            .find("name")
                            .unwrap_or("/")
                            .to_string();
        let crate_version = req.extensions
                               .get::<Router>()
                               .unwrap()
                               .find("version")
                               .unwrap_or("/")
                               .to_string();
        let krate = Crate {
            name: crate_name.clone(),
            version: crate_version.clone(),
        };

        let mut base_dir = self.crates_path.clone();
        base_dir.push(krate.name.clone());
        base_dir.push(krate.version.clone());
        debug!("try to get {:?}", krate);
        {
            let active = self.active_downloads.read().unwrap();
            if active.contains(&krate) {
                return self.redirect(&krate);
            }
        }

        if base_dir.exists() {
            let f = BufReader::new(krate.get_index_file(self.index_path.clone()));
            let cksum = f.lines()
                         .map(IndexFile::from_line)
                         .filter(|i| i.vers == krate.version)
                         .map(|i| i.cksum)
                         .next()
                         .unwrap();


            debug!("load cached file");
            base_dir.push("download");
            let file = File::open(base_dir.clone()).unwrap();
            let mut reader = BufReader::new(file);
            let mut data = Vec::new();
            reader.read_to_end(&mut data).unwrap();
            let mut hasher = Sha256::new();
            hasher.input(&data);
            if hasher.result_str() != cksum {
                warn!("Checksum of {:?} did not match ", krate);
                debug!("{} vs {}", hasher.result_str(), cksum);
                ::std::fs::remove_file(base_dir).unwrap();
                self.download(&krate);
                self.redirect(&krate)
            } else {
                Ok(Response::with((Status::Ok, data.as_slice())))
            }
        } else {
            self.download(&krate);
            self.redirect(&krate)
        }
    }
}

fn main() {
    env_logger::init().unwrap();
    let version: &str = &format!("{}.{}.{}",
                                 env!("CARGO_PKG_VERSION_MAJOR"),
                                 env!("CARGO_PKG_VERSION_MINOR"),
                                 env!("CARGO_PKG_VERSION_PATCH"));
    let matches = App::new("Crates Mirror")
                      .version(version)
                      .author(env!("CARGO_PKG_AUTHORS"))
                      .about(env!("CARGO_PKG_DESCRIPTION"))
                      .arg(Arg::with_name("config")
                               .short("c")
                               .long("config")
                               .required(true)
                               .value_name("FILE")
                               .help("Sets a config file")
                               .takes_value(true))
                      .get_matches();
    let config = Config::from_file(matches.value_of("config").unwrap());
    let mut base_dir = PathBuf::from(config.base_path.clone());
    if !base_dir.exists() {
        create_dir_all(base_dir.clone()).unwrap();
    }
    let url: &str = &config.listen_on.clone();
    base_dir.push("index");
    let repo = if !base_dir.exists() {
        let repo = Repository::clone(&config.registry_config.upstream_url, base_dir.clone())
                       .unwrap();
        {
            let mut config_file = base_dir.clone();
            config_file.push("config.json");
            let mut config_file = File::create(config_file).unwrap();
            write!(&mut config_file,
                   "{{\"dl\": \"http://{url}/api/v1/crates\", \"api\": \"http://{url}\"}}",
                   url = url)
                .unwrap();
            let sig = repo.signature().unwrap();
            let mut index = repo.index().unwrap();
            index.update_all(&["config.json"], None).unwrap();
            let id = index.write_tree_to(&repo).unwrap();
            let tree = repo.find_tree(id).unwrap();
            let parent = repo.find_commit(repo.refname_to_id("HEAD").unwrap()).unwrap();
            let id = repo.commit(Some("HEAD"),
                                 &sig,
                                 &sig,
                                 "Add local mirror",
                                 &tree,
                                 &[&parent])
                         .unwrap();
            repo.reset(&repo.find_object(id, None).unwrap(), ResetType::Hard, None).unwrap();
            if let Some(remote) = config.registry_config.origin_url.clone() {
                let mut callbacks = git2::RemoteCallbacks::new();
                callbacks.credentials(credentials);
                repo.remote("local", &remote).unwrap();
                let mut remote = repo.find_remote("local").unwrap();
                let mut opts = git2::PushOptions::new();
                opts.remote_callbacks(callbacks);
                remote.push(&["refs/heads/master"], Some(&mut opts)).unwrap();
            }
        }
        repo
    } else {
        Repository::open(base_dir.clone()).unwrap()
    };
    {
        let config = config.clone();
        std::thread::spawn(move || poll_index(repo, config));
    }
    let mut base_path = PathBuf::from(config.base_path.clone());
    base_path.push("crates");
    let mut index_path = PathBuf::from(config.base_path);
    index_path.push("index");

    let mirror = Mirror {
        remote_api: config.remote_api,
        crates_path: base_path,
        index_path: index_path,
        active_downloads: Arc::new(RwLock::new(HashSet::new())),
    };
    let mut router = Router::new();
    router.get("/api/v1/crates/:name/:version/download", mirror);

    debug!("startup finished");
    println!("finish to setup crates.io mirror. Point cargo repository to {}",
             config.registry_config
                   .origin_url
                   .clone()
                   .unwrap_or(format!("file://{}", base_dir.to_str().unwrap())));

    Iron::new(router)
        .http(url)
        .unwrap();
}


pub fn credentials(_url: &str,
                   user_from_url: Option<&str>,
                   _cred: git2::CredentialType)
                   -> Result<git2::Cred, git2::Error> {
    // TODO: allow more options
    if let Some(user) = user_from_url {
        let r = Cred::ssh_key_from_agent(user);
        return r;
    }
    Err(git2::Error::from_str("no authentication set"))
}

fn poll_index(repo: Repository, config: Config) {

    let mut origin = repo.find_remote("origin").unwrap();
    loop {
        ::std::thread::sleep(Duration::from_secs(config.poll_intervall.unwrap_or(60) as u64));
        origin.fetch(&["refs/heads/*:refs/heads/*"], None, None).unwrap();
        let head = repo.refname_to_id("HEAD").unwrap();
        let remote_head = repo.refname_to_id("refs/remotes/origin/master").unwrap();
        let head = repo.find_commit(head).unwrap();
        let remote_head = repo.find_commit(remote_head).unwrap();
        repo.merge_commits(&head, &remote_head, None).unwrap();

        if let Some(_) = config.registry_config.origin_url.clone() {
            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(credentials);
            let mut remote = repo.find_remote("local").unwrap();
            let mut opts = git2::PushOptions::new();
            opts.remote_callbacks(callbacks);
            remote.push(&["refs/heads/master"], Some(&mut opts)).unwrap();
        }

        info!("updated index");
    }

}
