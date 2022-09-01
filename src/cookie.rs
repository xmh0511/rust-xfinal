use jwt::{SignWithKey, VerifyWithKey};

use super::http_parser::Request;
pub use expedite::datetime::period::Period;
pub use expedite::datetime::time::Time;
use hmac::Hmac;
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

use chrono::TimeZone;

use chrono_tz::GMT;
use chrono_tz::US::Pacific;

pub struct Cookie {
    name: String,
    path: String,
    domain: String,
    max_age: Option<Time>,
    http_only: bool,
    data: BTreeMap<String, String>,
    secret_key: Arc<Hmac<Sha256>>,
}

fn cookie_str_to_map(s: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    for e in s.split(";") {
        match e.split_once("=") {
            Some((k, v)) => {
                map.insert(k.trim(), v.trim());
            }
            None => {
                continue;
            }
        }
    }
    map
}

impl Cookie {
    /// > Create a cookie object from Request
    /// >> - return a exist cookie if the client provides that
    /// >> - Otherwise, return a new cookie
    pub fn new(name: String, req: &Request) -> Self {
        let key = &*req.get_secret_key();
        let path = req.url_to_path();
        match req.get_header("Cookie") {
            Some(s) => match cookie_str_to_map(s).get(name.as_str()) {
                Some(&token) => {
                    match token.verify_with_key(key) {
                        Ok(x) => {
                            // let borrow:& mut BTreeMap<String, String> = & mut x;
                            return Cookie {
                                name,
                                path: String::from(path),
                                domain: String::new(),
                                max_age: None,
                                http_only: false,
                                data: x,
                                secret_key: req.get_secret_key(),
                            };
                        }
                        Err(_) => {}
                    }
                }
                None => {}
            },
            None => {}
        }
        Cookie {
            name,
            path: String::from(path),
            domain: String::new(),
            max_age: None,
            http_only: false,
            data: BTreeMap::new(),
            secret_key: req.get_secret_key(),
        }
    }

    /// > Set the cookie name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    /// > Get the cookie name
    pub fn get_name(&self) -> &String {
        &self.name
    }
    /// > Set the cookie path
    pub fn set_path(&mut self, path: String) {
        self.path = path
    }
    /// > Get the cookie path
    pub fn get_path(&self) -> &String {
        &self.path
    }
    /// > Set the cookie domain
    pub fn set_domain(&mut self, domain: String) {
        self.domain = domain;
    }
    /// > Get the cookie domain
    pub fn get_domain(&self) -> &String {
        &self.domain
    }

    /// > Set the cookie max_age
    pub fn set_max_age(&mut self, time: Time) {
        self.max_age = Some(time);
    }

    /// > Get the cookie max_age
    pub fn get_max_age(&self) -> &Option<Time> {
        &self.max_age
    }

    /// > Set the cookie http-only
    pub fn set_http_only(&mut self, v: bool) {
        self.http_only = v;
    }
    /// > Get the cookie http-only
    pub fn get_http_only(&self) -> bool {
        self.http_only
    }

    pub fn get_data<T: FromStr>(&self, k: String) -> Option<T> {
        match self.data.get(&k) {
            Some(v) => match v.parse() {
                Ok(v) => {
                    return Some(v);
                }
                Err(_) => {
                    return None;
                }
            },
            None => {
                return None;
            }
        }
    }

    pub fn insert<T: ToString>(&mut self, k: String, v: T) {
        self.data.insert(k, v.to_string());
    }

    pub fn gen_token(&self) -> Option<String> {
        match self.data.clone().sign_with_key(&*self.secret_key) {
            Ok(s) => Some(s),
            Err(_) => None,
        }
    }

    pub fn to_string(&self) -> Option<String> {
        let time = if let Some(ref t) = self.max_age {
            let time = Pacific
                .ymd(t.date.year as i32, t.date.month, t.date.day)
                .and_hms(t.hours, t.minutes, t.seconds);
            let gmt = time.with_timezone(&GMT);
            gmt.to_rfc2822()
        } else {
            String::from("Session")
        };
        let domain = {
            if self.domain == "" {
                "".to_string()
            } else {
                format!("{};", self.domain)
            }
        };
        let http_only = {
            if self.http_only {
                ""
            } else {
                "HttpOnly;"
            }
        };
        if let Some(token) = self.gen_token() {
            let r = format!(
                "{name}={token}; path={path}; {domain} Expires={time}; {http_only}",
                name = self.name,
                path = self.path,
                time = time.to_string()
            );
            Some(r)
        } else {
            None
        }
    }
}
