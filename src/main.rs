// Copyright (C) 2016 by Georg Semmler

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
#![deny(warnings)]
extern crate curl;
extern crate git2;
extern crate iron;
extern crate router;
extern crate serde_json;
extern crate toml;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate clap;
extern crate env_logger;
extern crate sha2;

use std::collections::HashSet;
use std::fs::{create_dir_all, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use clap::{App, Arg};
use curl::easy::Easy;
use git2::{Cred, CredentialType, Repository};
use sha2::{Digest, Sha256};

use iron::modifiers::Redirect;
use iron::prelude::*;
use iron::status;
use iron::Handler;
use iron::Url;
use router::Router;

#[derive(Debug, Deserialize, Clone)]
struct GitConfig {
    upstream_url: String,
    origin: Option<OriginConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct OriginConfig {
    url: String,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Config {
    base_path: String,
    remote_api: String,
    listen_on: String,
    publish_url: String,
    registry_config: GitConfig,
    poll_intervall: Option<i32>,
}

impl Config {
    pub fn from_file(path: &str) -> Config {
        let mut config_toml = String::new();

        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_e) => panic!("Could not find config file {}!", path),
        };
        file.read_to_string(&mut config_toml)
            .unwrap_or_else(|err| panic!("Error while reading config: [{}]", err));
        toml::from_str(&config_toml)
            .unwrap_or_else(|err| panic!("Error while parsing config: [{}]", err))
    }
}

#[derive(Deserialize)]
struct IndexFile {
    vers: String,
    cksum: String,
}

impl IndexFile {
    fn from_line(l: Result<String, ::std::io::Error>) -> IndexFile {
        serde_json::from_str(&l.unwrap()).unwrap()
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct Crate {
    name: String,
    version: String,
}

impl Crate {
    fn get_index_file(&self, mut index: PathBuf) -> File {
        let name = self
            .name
            .chars()
            .flat_map(|c| c.to_lowercase())
            .collect::<String>();
        match name.len() {
            e if e > 3 => {
                index.push(&self.name[0..2]);
                index.push(&self.name[2..4]);
            }
            3 => {
                index.push("3");
                index.push(&self.name[0..1]);
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
        let url = Url::parse(&format!(
            "{}/api/v1/crates/{}/{}/download",
            self.remote_api, krate.name, krate.version
        ))
        .unwrap();
        Ok(Response::with((status::TemporaryRedirect, Redirect(url))))
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
        let url = format!(
            "{}/api/v1/crates/{}/{}/download",
            self.remote_api, krate.name, krate.version,
        );
        debug!("try to download {:?} from {}", krate, url);
        handle.url(&url).unwrap();
        handle.follow_location(true).unwrap();
        {
            let mut transfer = handle.transfer();
            transfer
                .write_function(|data| {
                    debug!("get part of {:?}", krate);
                    Ok(writer.write(data).unwrap())
                })
                .unwrap();
            match transfer.perform() {
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        "fetch of {:?} failed because {:?}! retry {}",
                        krate, e, retry_count
                    );
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
        let crate_name = req
            .extensions
            .get::<Router>()
            .unwrap()
            .find("name")
            .unwrap_or("/")
            .to_string();
        let crate_version = req
            .extensions
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
        debug!("try to get {:?}", base_dir);
        {
            let active = self.active_downloads.read().unwrap();
            if active.contains(&krate) {
                debug!("already downloaded");
                return self.redirect(&krate);
            }
        }
        if base_dir.exists() {
            let f = BufReader::new(krate.get_index_file(self.index_path.clone()));
            let cksum = f
                .lines()
                .map(IndexFile::from_line)
                .find(|i| i.vers == krate.version)
                .map(|i| i.cksum)
                .unwrap();

            debug!("load cached file");
            base_dir.push("download");
            let file = File::open(base_dir.clone()).unwrap();
            let mut reader = BufReader::new(file);
            let mut data = Vec::new();
            reader.read_to_end(&mut data).unwrap();
            let mut hasher = Sha256::new();
            hasher.input(&data);
            let local_cksum = format!("{:x}", hasher.result());
            if local_cksum != cksum {
                warn!("Checksum of {:?} did not match ", krate);
                debug!("{} vs {:?}", local_cksum, cksum);
                ::std::fs::remove_file(base_dir).unwrap();
                self.download(&krate);
                self.redirect(&krate)
            } else {
                Ok(Response::with((status::Ok, data.as_slice())))
            }
        } else {
            self.download(&krate);
            self.redirect(&krate)
        }
    }
}

fn main() {
    env_logger::init();
    let version: &str = &format!(
        "{}.{}.{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH")
    );
    let matches = App::new("Crates Mirror")
        .version(version)
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .required(true)
                .value_name("FILE")
                .help("Sets a config file")
                .takes_value(true),
        )
        .get_matches();
    let config = Config::from_file(matches.value_of("config").unwrap());
    let mut base_dir = PathBuf::from(config.base_path.clone());
    if !base_dir.exists() {
        create_dir_all(base_dir.clone()).unwrap();
    }
    let url: &str = &std::env::var("PUBLISH_URL").unwrap_or(config.publish_url.clone());
    let listen_on: &str = &config.listen_on.clone();
    base_dir.push("index");
    let repo = if !base_dir.exists() {
        let repo =
            Repository::clone(&config.registry_config.upstream_url, base_dir.clone()).unwrap();
        {
            let mut config_file_path = base_dir.clone();
            config_file_path.push("config.json");
            let mut config_file = File::create(config_file_path.clone()).unwrap();
            write!(
                &mut config_file,
                "{{\"dl\": \"{url}/api/v1/crates\", \"api\": \"{url}\"}}",
                url = url
            )
            .unwrap();

            let repo_path = repo.workdir().unwrap();
            // git add $file
            let mut index = repo.index().unwrap();
            let mut repo_path = repo_path.iter();
            let dst = config_file_path
                .iter()
                .skip_while(|s| Some(*s) == repo_path.next())
                .collect::<PathBuf>();
            index.add_path(&dst).unwrap();
            index.write().unwrap();
            let tree_id = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();

            // git commit -m "..."
            let head = repo.head().unwrap();
            let parent = repo.find_commit(head.target().unwrap()).unwrap();
            let sig = repo.signature().unwrap();
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "Add local mirror",
                &tree,
                &[&parent],
            )
            .unwrap();

            if let Some(ref remote) = config.registry_config.origin {
                let mut callbacks = git2::RemoteCallbacks::new();
                callbacks.credentials(|url, user, cred| credentials(url, user, cred, remote));
                callbacks.transfer_progress(progress_monitor);
                repo.remote("local", &remote.url).unwrap();
                let mut remote = repo.find_remote("local").unwrap();
                let mut opts = git2::PushOptions::new();
                opts.remote_callbacks(callbacks);
                remote
                    .push(&["refs/heads/master"], Some(&mut opts))
                    .unwrap();
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
        index_path,
        active_downloads: Arc::new(RwLock::new(HashSet::new())),
    };
    let mut router = Router::new();
    router.get(
        "/api/v1/crates/:name/:version/download",
        mirror,
        "get-crate",
    );

    debug!("startup finished");
    println!(
        "finish to setup crates.io mirror. Point cargo repository to {}",
        config
            .registry_config
            .origin
            .map(|o| o.url)
            .clone()
            .unwrap_or_else(|| format!("file://{}", base_dir.to_str().unwrap()))
    );

    Iron::new(router).http(listen_on).unwrap();
}

fn progress_monitor(progress: git2::Progress) -> bool {
    debug!(
        "total :{}, local: {}, remote: {}",
        progress.total_objects(),
        progress.local_objects(),
        progress.received_objects()
    );
    true
}

fn credentials(
    url: &str,
    user_from_url: Option<&str>,
    cred: git2::CredentialType,
    origin_config: &OriginConfig,
) -> Result<git2::Cred, git2::Error> {
    let mut error = git2::Error::from_str(&format!("Failed to find credentials for {}", url));
    debug!("credentials");
    if cred.contains(CredentialType::USER_PASS_PLAINTEXT) {
        if let (&Some(ref u), &Some(ref p)) = (&origin_config.username, &origin_config.password) {
            debug!("from username/password");
            match Cred::userpass_plaintext(u, p) {
                Err(e) => {
                    debug!("Error: {:?}", e);
                    error = e;
                }
                Ok(c) => {
                    debug!("Ok!");
                    return Ok(c);
                }
            }
        }
    }
    if cred.contains(CredentialType::DEFAULT) {
        let config = git2::Config::open_default()?;
        match Cred::credential_helper(&config, url, user_from_url) {
            Err(e) => {
                debug!("Error: {:?}", e);
                error = e;
            }
            Ok(c) => {
                debug!("Ok!");
                return Ok(c);
            }
        }
    }
    if cred.contains(CredentialType::SSH_KEY) {
        if let Some(user) = user_from_url {
            debug!("from ssh agent");
            match Cred::ssh_key_from_agent(user) {
                Err(e) => {
                    debug!("Error: {:?}", e);
                    error = e;
                }
                Ok(c) => {
                    debug!("Ok");
                    return Ok(c);
                }
            }
        }
    }
    Err(error)
}

fn poll_index(repo: Repository, config: Config) {
    let mut origin = repo.find_remote("origin").unwrap();
    loop {
        ::std::thread::sleep(Duration::from_secs(
            config.poll_intervall.unwrap_or(60) as u64
        ));
        'retry: for i in 0..20 {
            match try_merge(&repo, &config, &mut origin) {
                Ok(()) => break 'retry,
                Err(ref e) if i == 19 => {
                    panic!("{:?}", e);
                }
                _ => {
                    debug!("Retry {}", i);
                }
            }
        }
    }
}

fn try_merge(
    repo: &Repository,
    config: &Config,
    origin: &mut git2::Remote,
) -> Result<(), git2::Error> {
    origin.fetch(&["master"], None, None)?;
    let head = repo.head()?;

    let parent = repo.find_commit(head.target().unwrap())?;
    let remote = repo.find_reference("refs/remotes/origin/master")?;
    let c = repo.reference_to_annotated_commit(&remote)?;
    let mut checkout = ::git2::build::CheckoutBuilder::new();
    let mut merge_option = ::git2::MergeOptions::new();
    let mut index = repo.index()?;
    let old_tree = repo.find_tree(index.write_tree()?)?;
    repo.merge(
        &[&c],
        Some(merge_option.file_favor(::git2::FileFavor::Theirs)),
        Some(checkout.force()),
    )?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let diff = repo.diff_tree_to_tree(Some(&old_tree), Some(&tree), None)?;
    if diff.stats()?.files_changed() > 0 {
        let sig = repo.signature()?;
        repo.commit(Some("HEAD"), &sig, &sig, "Merge", &tree, &[&parent])?;

        if let Some(ref remote) = config.registry_config.origin {
            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(|url, user, cred| credentials(url, user, cred, remote));
            callbacks.transfer_progress(progress_monitor);
            let mut remote = repo.find_remote("local")?;
            let mut opts = git2::PushOptions::new();
            opts.remote_callbacks(callbacks);
            remote.push(&["refs/heads/master"], Some(&mut opts))?;
        }
        debug!("updated index");
    } else {
        trace!("Nothing to update");
        repo.cleanup_state()?;
    }
    Ok(())
}
