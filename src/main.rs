use std::fs::File;
use std::io::{self, Read, BufReader, Write, BufWriter};
use std::string::String;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use std::fmt;
use std::result::Result;
use std::ascii::AsciiExt;
use std::path::PathBuf;
use std::iter::FromIterator;

extern crate hyper;
use hyper::client::Client;

extern crate yaml_rust;
use yaml_rust::YamlLoader;
use yaml_rust::yaml::Yaml;

#[macro_use]
extern crate clap;
use clap::{Arg, App};

#[derive(PartialEq)]
enum OutputFormat {
    DomainsOnly,
    Hosts,
    Dnsmasq,
    Unbound,
    Pdnsd
}

impl FromStr for OutputFormat {
    type Err = ();
    fn from_str(format: &str) -> Result<Self, ()> {
        let variant = match format {
            "domains"       => OutputFormat::DomainsOnly,
            "hosts"      => OutputFormat::Hosts,
            "dnsmasq"      => OutputFormat::Dnsmasq,
            "unbound"      => OutputFormat::Unbound,
            "pdnsd"      => OutputFormat::Pdnsd,
            _ => {
                return Err(());
            }
        };
        Ok(variant)
    }
}

#[derive(PartialEq)]
enum Target {
    NXDOMAIN,
    IpAddr(IpAddr)
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let formatted = match self {
            &Target::NXDOMAIN => String::from("NXDOMAIN"),
            &Target::IpAddr(addr) => format!("{}", addr)
        };
        write!(f, "{}", formatted)
    }
}

impl FromStr for Target {
    type Err = ();
    fn from_str(target: &str) -> Result<Self, ()> {
        if let Ok(addr) = Ipv6Addr::from_str(target) {
            return Ok(Target::IpAddr(IpAddr::V6(addr)));
        } else

        if let Ok(addr) = Ipv4Addr::from_str(target) {
            return Ok(Target::IpAddr(IpAddr::V4(addr)));
        }

        if target.to_ascii_uppercase() == "NXDOMAIN" {
            return Ok(Target::NXDOMAIN);
        }
        return Err(());
    }
}

fn main() {
    let m = App::new("baddns - DNS based adblocking with ease")
        .version("0.1")
        .arg(Arg::with_name("format")
            .help("Specify an output format.")
            .short("f")
            .long("format")
            .possible_values(&["domains", "hosts", "dnsmasq", "unbound", "pdnsd"])
            .value_name("FORMAT")
            .takes_value(true)
            .default_value("hosts"))
        .arg(Arg::with_name("target")
            .help("Specify the target (NXDOMAIN or IPv4/v6 address).")
            .short("t")
            .long("target")
            .value_name("TARGET")
            .takes_value(true)
            .default_value("127.0.1.1"))
        .arg(Arg::with_name("out")
            .help("Specify an output file. [default: stdout]")
            .short("o")
            .long("out")
            .value_name("FILE")
            .takes_value(true))
        .get_matches();

    // Parse format and target from arguments
    let format = value_t!(m, "format", OutputFormat).unwrap_or_else(|e| e.exit());
    let target = value_t!(m, "target", Target).unwrap_or_else(|e| e.exit());

    // Catch invalid format/target combinations
    match target {
        Target::IpAddr(_) => {
            if format == OutputFormat::Pdnsd {
                writeln!(&mut io::stderr(),
                         "Error: pdnsd only supports NXDOMAIN (start with -t nxdomain).").unwrap();
                std::process::exit(1);
            }
        }
        Target::NXDOMAIN => {
            if format == OutputFormat::Hosts {
                writeln!(&mut io::stderr(),
                         "Error: /etc/hosts format doesn't support NXDOMAIN as target.").unwrap();
                std::process::exit(1);
            }
        }
    }

    // Assign output file from arguments
    let out = match m.value_of("out") {
        Some(filename) => {
            match File::create(PathBuf::from(filename)) {
                Ok(f) => Box::new(BufWriter::new(f)) as Box<Write>,
                Err(e) => panic!("{}", e)
            }
        },
        None => Box::new(BufWriter::new(io::stdout())) as Box<Write>
    };

    // yaml config keys
    let keys = vec!["domainlists"];

    // Open and parse conf
    let docs = YamlLoader::load_from_str(&load_conf("conf.yaml").unwrap()).unwrap();

    // Collect lists from conf
    let urls = keys.iter()
        .fold(HashSet::new(), |mut l, k| {
            l.extend(get_urls_from_conf(&docs[0], k)); l
        });

    // Load valid top level domains from iana.org
    let valid_tlds = fetch_url("http://data.iana.org/TLD/tlds-alpha-by-domain.txt").unwrap();

    // Fetch lists and parse domains
    let domains: HashSet<String> = fetch_domainlists(urls)
        .unwrap()
        .into_iter()
        .map(|e| parse_hosts_entry(&e).to_string())
        .collect();

    let domains = validate_domains(domains, HashSet::from_iter(valid_tlds));
    // Write generated domain list to file
    write_gen_list(domains, target, format, out).unwrap();
}

fn get_urls_from_conf<'a>(root: &'a Yaml, key: &str) -> Vec<&'a str> {
    match root[key].as_vec() {
        Some(list) => list.into_iter()
            .map(|u| u.as_str().unwrap())
            .collect::<Vec<&str>>(),
        None => {
            writeln!(&mut io::stderr(),
                     "Warning: unable to load urls for key {}",
                     key)
                .unwrap();
            Vec::new()
        }
    }
}

fn fetch_domainlists(urls: HashSet<&str>) -> io::Result<HashSet<String>> {
    let mut domains = HashSet::new();
    for url in urls {
        if let Ok(lines) = fetch_url(url) {
            domains.extend(lines);
        } else {
            writeln!(&mut io::stderr(), "Error: Unable to fetch: {}", url).unwrap();
        }
    }
    Ok(domains)
}

fn fetch_url(url: &str) -> io::Result<Vec<String>> {
    let client = Client::new();
    if let Ok(mut res) = client.get(url).send() {
        let mut content = String::new();
        try!(res.read_to_string(&mut content));
        let lines: Vec<String> = content.lines()
            .into_iter()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.to_lowercase())
            .collect();
        return Ok(lines);
    }
    return Ok(Vec::new());
}

fn load_conf(filename: &str) -> io::Result<String> {
    let mut content = String::new();
    try!(BufReader::new(try!(File::open(filename)))
        .read_to_string(&mut content));
    Ok(content)
}

fn parse_hosts_entry<'a>(line: &'a str) -> &'a str {
    let mut domains: Vec<&'a str> = line.split_whitespace()
        .into_iter()
        .filter(|&i| IpAddr::from_str(i).is_err())
        .collect();

    // Sanity check to ensure a line contains only one domain
    if domains.len() == 1 {
        return domains.pop().unwrap();
    }

    writeln!(&mut io::stderr(),
             "Ignoring entry: {} (bogus line)",
             domains.join("")).unwrap();
    return "";
}

fn validate_domains(domains: HashSet<String>, valid_tlds: HashSet<String>) -> HashSet<String> {
    let mut valid_domains = HashSet::with_capacity(domains.len());
    for d in domains {
        let parts: Vec<&str> = d.split('.').collect();

        // Check domain has at least to parts (e.g.: google.com)
        if parts.len() < 2 {
            writeln!(&mut io::stderr(), "Ignoring entry: {} (no valid domain)", d).unwrap();
            continue;
        }

        // Check if tld is valid
        let tld = parts.last().unwrap().to_string();
        if !valid_tlds.contains(&tld) {
            writeln!(&mut io::stderr(), "Ignoring entry: {} (invalid tld)", d).unwrap();
            continue;
        }
        valid_domains.insert(d.clone());
    }
    valid_domains
}

fn write_gen_list(domains: HashSet<String>, target: Target,
                  format: OutputFormat, mut writer: Box<Write>) -> io::Result<()> {
    for domain in domains {
        let formatted_domain = match format {
            OutputFormat::DomainsOnly => domain.to_string(),
            OutputFormat::Hosts => format!("{}\t{}\n", target, domain),
            OutputFormat::Pdnsd => format!("neg {{ name={}; types=domain; }}\n", domain),
            OutputFormat::Unbound => {
                match target {
                    Target::NXDOMAIN => format!("local-zone: \"{}\" static\n", domain),
                    _ => format!("local-zone: \"{0}\" redirect\nlocal-data: \"{0} A {1}\"\n",
                                domain, target)
                }
            },
            OutputFormat::Dnsmasq => {
                match target {
                    Target::NXDOMAIN => format!("server=/{}/\n", domain),
                    Target::IpAddr(addr) => format!("address=/{}/{}\n", domain, addr)
                }
            }
        };
        try!(writer.write(formatted_domain.as_bytes()));
    }
    writer.flush()
}
