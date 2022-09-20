use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;

mod thread_pool;

mod http_parser;

use http_parser::WsRouterValue;
pub use http_parser::{
    ConnectionData, MiddleWare, Request, Response, Router, RouterMap, RouterValue, ServerConfig,
    Websocket, WebsocketEvent, WsMessage, WsRouter,
};

pub use rust_xfinal_macro::end_point;

pub use http_parser::connection::http_response_table::{
    CONNECT, DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, TRACE,
};

use http_parser::connection::http_response_table::get_httpmethod_from_code;

pub use tera;

pub use serde_json;

pub type JsonValue = serde_json::Value;

pub mod cookie;

pub use cookie::Period;

pub use chrono;
pub use chrono_tz;
pub use hmac;
pub use sha2;

pub use base64;

pub use sha1;

use hmac::{Hmac, Mac};
use sha2::Sha256;
pub use uuid;

pub trait SerializationMethods {
    fn serialize(&self) -> Vec<&'static str>;
}

impl SerializationMethods for u8 {
    fn serialize(&self) -> Vec<&'static str> {
        let m = get_httpmethod_from_code(*self);
        let mut r = Vec::new();
        r.push(m);
        r
    }
}

impl SerializationMethods for &[u8] {
    fn serialize(&self) -> Vec<&'static str> {
        let mut r = Vec::new();
        for e in *self {
            let m = get_httpmethod_from_code(*e);
            r.push(m);
        }
        r
    }
}

impl<const I: usize> SerializationMethods for [u8; I] {
    fn serialize(&self) -> Vec<&'static str> {
        let mut r = Vec::new();
        for e in *self {
            let m = get_httpmethod_from_code(e);
            r.push(m);
        }
        r
    }
}

#[derive(Debug)]
pub struct EndPoint {
    pub port: u16,
    pub ip_address: [u8; 4],
}

pub struct HttpServer {
    end_point: EndPoint,
    thread_number: u16,
    router: HashMap<String, RouterValue>,
    ws_router: HashMap<String, WsRouterValue>,
    config_: ServerConfig,
}

pub struct RouterRegister<'a> {
    server: &'a mut HttpServer,
    path: &'a str,
    methods: Vec<&'a str>,
}

impl<'a> RouterRegister<'a> {
    pub fn reg<F>(&mut self, f: F)
    where
        F: Router + Send + Sync + 'static + Clone,
    {
        for e in &self.methods {
            let router_path = format!("{}{}", e, self.path);
            self.server
                .router
                .insert(router_path, (None, Arc::new(f.clone())));
        }
    }

    pub fn reg_with_middlewares<F>(
        &mut self,
        middlewares: Vec<Arc<dyn MiddleWare + Send + Sync>>,
        f: F,
    ) where
        F: Router + Send + Sync + 'static + Clone,
    {
        for e in &self.methods {
            let router_path = format!("{}{}", e, self.path);
            self.server.router.insert(
                router_path,
                (Some(middlewares.clone()), Arc::new(f.clone())),
            );
        }
    }
}

pub struct WsRouterRegister<'a> {
    server: &'a mut HttpServer,
    path: &'a str,
}

impl<'a> WsRouterRegister<'a> {
    pub fn reg<F>(&mut self, f: F)
    where
        F: WsRouter + Send + Sync + 'static + Clone,
    {
        self.server
            .ws_router
            .insert(self.path.to_string(), (None, Arc::new(f.clone())));
    }

    pub fn reg_with_middlewares<F>(
        &mut self,
        middlewares: Vec<Arc<dyn MiddleWare + Send + Sync>>,
        f: F,
    ) where
        F: WsRouter + Send + Sync + 'static + Clone,
    {
        self.server.ws_router.insert(
            self.path.to_string(),
            (Some(middlewares.clone()), Arc::new(f.clone())),
        );
    }
}

impl HttpServer {
    /// > create an instance of http server
    /// >> - end: use `end_point![0.0.0.0:8080]` to construct `EndPoint`
    /// >> - count: specify the size of thread pool
    pub fn create(end: EndPoint, count: u16) -> Self {
        let key = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("./secret.key")
        {
            Ok(mut file) => {
                let mut s = String::new();
                match file.read_to_string(&mut s) {
                    Ok(size) => {
                        if size == 0 {
                            let s = uuid::Uuid::new_v4().to_string();
                            file.write(s.as_bytes())
                                .expect("write new secret key error");
                            s
                        } else {
                            s
                        }
                    }
                    Err(e) => {
                        panic!("initial secret key error:{}", e.to_string())
                    }
                }
            }
            Err(e) => {
                panic!("initial secret key error:{}", e.to_string())
            }
        };
        type HmacSha256 = Hmac<Sha256>;
        let mac = match HmacSha256::new_from_slice(key.as_bytes()) {
            Ok(r) => r,
            Err(e) => {
                panic!("HmacSha256::new_from_slice error:{}", e.to_string())
            }
        };
        Self {
            end_point: end,
            thread_number: count,
            router: HashMap::new(),
            ws_router: HashMap::new(),
            config_: ServerConfig {
                upload_directory: String::from("./upload"),
                read_timeout: 5 * 1000,
                chunk_size: 1024 * 5,
                write_timeout: 5 * 1000,
                open_log: false,
                max_body_size: 3 * 1024 * 1024,
                max_header_size: 3 * 1024 * 1024,
                read_buff_increase_size: 1024,
                secret_key: Arc::new(mac),
                ws_read_timeout: 5 * 60 * 1000,
                ws_write_timeout: 5 * 60 * 1000,
                ws_frame_size: 65535,
            },
        }
    }

    fn create_directory(&self) -> io::Result<bool> {
        let _ = std::fs::create_dir(self.config_.upload_directory.clone())?;
        Ok(true)
    }
    /// > This method specifies the value of time when waiting for the read from the client.
    /// >> - [unit: millisecond]
    pub fn set_read_timeout(&mut self, millis: u32) {
        self.config_.read_timeout = millis;
    }

    /// > This method specifies the value of time when waiting for the read of the client
    /// >> - [unit: millisecond]
    pub fn set_write_timeout(&mut self, millis: u32) {
        self.config_.write_timeout = millis;
    }

    /// > Specifiy each chunk size when responding to the client by using Chunked Transfer,
    /// >> - [unit: byte]
    pub fn set_chunksize(&mut self, size: u32) {
        self.config_.chunk_size = size;
    }

    /// > The switch to output the error in the connection the server has caught
    pub fn open_server_log(&mut self, open: bool) {
        self.config_.open_log = open;
    }

    /// > Specify the maximum size of body in a connection the server can handle
    /// >> - [unit: byte]
    pub fn set_max_body_size(&mut self, size: usize) {
        self.config_.max_header_size = size;
    }

    /// > Specify the maximum size of http header in a connection the server can handle
    /// >> - [unit: byte]
    pub fn set_max_header_size(&mut self, size: usize) {
        self.config_.max_body_size = size;
    }

    /// > Specify the increased size of buffers used for taking the content of the stream in a connection
    /// >> - [unit: byte]
    pub fn set_read_buff_increase_size(&mut self, size: usize) {
        self.config_.read_buff_increase_size = size;
    }

    /// > This method specifies the value of time when waiting for the websocket read from the client.
    /// >> - [unit: millisecond]
    pub fn set_ws_readtimeout(&mut self, millis: u32) {
        self.config_.ws_read_timeout = millis;
    }

    /// > This method specifies the value of time when waiting for the websocket write to the client.
    /// >> - [unit: millisecond]
    pub fn set_ws_writetimeout(&mut self, millis: u32) {
        self.config_.ws_write_timeout = millis;
    }

    /// > This method specifies the size of the websocket's fragment
    /// >> - [unit: byte]
    pub fn set_ws_frame_size(&mut self, size: usize) {
        if size < 126 {
            panic!("shall be larger than or equal to 126");
        }
        self.config_.ws_frame_size = size;
    }

    /// > To start a http server
    /// >> - This is a block method, which implies all set to the instance of HttpServer
    ///  should precede the call of this method
    pub fn run(&mut self) {
        let [a, b, c, d] = self.end_point.ip_address;
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), self.end_point.port);
        let listen = TcpListener::bind(socket);
        self.not_found_default_if_not_set();
        match self.create_directory() {
            Ok(_) => {}
            Err(e) => match e.kind() {
                io::ErrorKind::AlreadyExists => {}
                _ => {
                    panic!("{}", e.to_string())
                }
            },
        };
        let safe_router = Arc::new(self.router.clone());
        let safe_ws_router = Arc::new(self.ws_router.clone());
        let conn_data = Arc::new(ConnectionData {
            router_map: safe_router,
            ws_router_map: safe_ws_router,
            server_config: self.config_.clone(),
        });
        match listen {
            Ok(x) => {
                let mut pool =
                    thread_pool::ThreadPool::new(self.thread_number, http_parser::handle_incoming);
                for conn in x.incoming() {
                    match conn {
                        Ok(stream) => {
                            let conn_data = conn_data.clone();
                            match pool.poll((conn_data, stream)) {
                                Ok(_) => {}
                                Err(e) => {
                                    if self.config_.open_log {
                                        let now = http_parser::get_current_date();
                                        println!(
                                            "[{}] >>> error in send connection: {}",
                                            now,
                                            e.to_string()
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if self.config_.open_log {
                                let now = http_parser::get_current_date();
                                println!("[{}] >>> error on incoming:{}", now, e.to_string());
                            }
                        }
                    }
                }
                pool.join();
            }
            Err(e) => {
                panic!("listen error, the reason is: {}", e.to_string());
            }
        }
    }

    /// > Register a router
    /// >> - methods: Http Method
    /// >>> allow the form: single method `GET`, or multiple methods `[GET, HEAD]`
    /// >> - path: Http Url to which the router respond
    /// # Usage:
    ///
    /// > HttpServer::route(HttpServer::GET, "/").reg(...)
    /// >> - the call of `reg` registers the action
    /// >>> - the argument shall satisfy the trait Router
    /// >>> - Router is automatically implemented for type fn and FnMut that takes two parameters `&Request` and `& mut Response`
    ///
    /// > HttpServer::route(HttpServer::GET, "/").reg_with_middlewares(...)
    /// >> - register a router with a set of middlwares
    /// >>> - The first argument is a set of middlwares
    /// >>> - A middleware satisfies trait `MiddleWare`
    ///
    /// > In the above cases, the path can a wildcard url, such as `/path/*`
    /// >> - A valid wildcard path cannot be `/*`
    ///
    pub fn route<'a, T: SerializationMethods>(
        &'a mut self,
        methods: T,
        path: &'a str,
    ) -> RouterRegister<'_> {
        //let method = get_httpmethod_from_code(M);
        if path.trim() == "/*" {
            panic!("/* => wildcard of root path is not permitted!")
        }
        RouterRegister {
            server: self,
            methods: methods.serialize(),
            path,
        }
    }

	/// > Register a websocket router
    pub fn route_ws<'a>(&'a mut self, path: &'a str) -> WsRouterRegister<'a> {
        WsRouterRegister { server: self, path }
    }

    /// > Specify the action when a request does not have a corresponding registered router
    /// >> - The framework has a preset action, you can overwrite it by using this method
    /// >> - The argument shall satisfy constraint: Router + Send + Sync + 'static
    pub fn set_not_found<F>(&mut self, f: F)
    where
        F: Router + Send + Sync + 'static,
    {
        self.router
            .insert(String::from("NEVER_FOUND_FOR_ALL"), (None, Arc::new(f)));
    }

    fn not_found_default_if_not_set(&mut self) {
        let r = &self.router.get(&String::from("NEVER_FOUND_FOR_ALL"));
        if let None = *r {
            self.set_not_found(|_req: &Request, res: &mut Response| {
                res.write_state(404);
            });
        }
    }
}

/// This macro is used to conveniently construct a set of middlwares
#[macro_export]
macro_rules! inject_middlewares {
	($($m:expr),*) => {
		{
			use std::sync::Arc;
			type T = Arc<dyn MiddleWare + Send + Sync>;
			let x = vec![$( Arc::new($m) as T ,)*];
			x
		}
	};
}

// #[macro_export]
// macro_rules! end_point {
//     ($a:expr,$b:expr,$c:expr,$d:expr ; $port:expr) => {{
//         let x = http_server::EndPoint {
//             port: $port as u16,
//             ip_address: [$a as u8, $b as u8, $c as u8, $d as u8],
//         };
//         x
//     }};
// }
