use super::{
    BodyContent, MultiMap, Request, Response, ResponseChunkMeta, ResponseRangeMeta, WsRouter,
    WsRouterValue,
};
use super::{BodyType, ConnectionData};
use sha1::{Digest, Sha1};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

pub(crate) fn exist_pair<'a>(k: &str, header: &'a HashMap<&str, &str>) -> (bool, Option<&'a str>) {
    let ak = header.keys().find(|&&ak| {
        if k.to_lowercase() == ak.to_lowercase() {
            true
        } else {
            false
        }
    });
    match ak {
        Some(&s) => {
            return (true, Some(header.get(s).unwrap()));
        }
        None => {
            return (false, None);
        }
    }
}

pub(crate) fn is_websocket_upgrade(
    method: &str,
    header: &HashMap<&str, &str>,
) -> (bool, String, String) {
    if method.to_lowercase() == "get" {
        let upgrade = exist_pair("Upgrade", header);
        let connection = exist_pair("Connection", header);
        let sec_websocket_key = exist_pair("Sec-WebSocket-Key", header);
        let version = exist_pair("Sec-WebSocket-Version", &header);
        if upgrade.0 == true
            && connection.0 == true
            && sec_websocket_key.0 == true
            && version.0 == true
        {
            if "websocket" == upgrade.1.unwrap().to_lowercase()
                && "upgrade" == connection.1.unwrap().to_lowercase()
            {
                return (
                    true,
                    version.1.unwrap().trim().to_string(),
                    sec_websocket_key.1.unwrap().trim().to_string(),
                );
            }
        }
    }
    (false, String::new(), String::new())
}

#[derive(Debug)]
pub enum WsMessage {
    Open,
    Message(Vec<u8>, u8),
    Close,
}

pub struct Websocket {
    conn: Arc<TcpStream>,
    write_mutex: Arc<Mutex<()>>,
    fragment_size: usize,
}
impl Websocket {
    pub fn clone(&self) -> Self {
        Websocket {
            conn: Arc::clone(&self.conn),
            write_mutex: Arc::clone(&self.write_mutex),
            fragment_size: self.fragment_size,
        }
    }
    pub fn write(&self, data: Vec<u8>, opcode: u8) {
        let len = data.len();
        //println!("total len:{}", len);
        let mut writer = BufWriter::new(self.conn.as_ref());
        if len <= 125 {
            let first_byte = 0b10000000u8 | opcode;
            let second_byte = len as u8;
            let mut buffs = Vec::new();
            buffs.push(first_byte);
            buffs.push(second_byte);
            buffs.extend_from_slice(&data);
            let lock_guard = self.write_mutex.lock().unwrap();
            match writer.write(&buffs) {
                Ok(_) => {}
                Err(_) => {
                    let _ = self.conn.shutdown(std::net::Shutdown::Both);
                }
            }
            drop(lock_guard);
        } else if len >= 126 {
            let fragment_size = self.fragment_size;
            let mut fragment_count = {
                let mut count = len / fragment_size;
                if (len % fragment_size) != 0 {
                    count += 1;
                }
                count
            };
            //println!("fragment_count:{}", fragment_count);
            let mut start_pos = 0usize;
            let lock_guard = self.write_mutex.lock().unwrap();
            while fragment_count > 0 {
                let mut buffs = Vec::new();
                fragment_count -= 1;
                let mut end_pos = start_pos + fragment_size;
                if end_pos >= len {
                    end_pos = len;
                }
                let fragment_data = &data[start_pos..end_pos];
                let first_byte = {
                    if start_pos == 0 {
                        // 首个包
                        0b00000000u8 | opcode
                    } else {
                        if fragment_count > 0 {
                            //中间的包,非最后一个
                            0
                        } else {
                            //分片最后一个包
                            0b10000000u8
                        }
                    }
                };
                buffs.push(first_byte);
                let actual_write_size = end_pos - start_pos;
                if actual_write_size >= 126 {
                    if actual_write_size <= u16::MAX as usize {
                        let second_byte = 126u8;
                        let payload = (actual_write_size as u16).to_be_bytes();
                        buffs.push(second_byte);
                        buffs.extend_from_slice(&payload);
                    } else if actual_write_size as u64 <= u64::MAX {
                        let second_byte = 127u8;
                        let payload = (actual_write_size as u64).to_be_bytes();
                        buffs.push(second_byte);
                        buffs.extend_from_slice(&payload);
                    }
                } else {
                    let second_byte = actual_write_size as u8;
                    buffs.push(second_byte);
                }
                //println!("{:?}", buffs);
                buffs.extend_from_slice(fragment_data);
                match writer.write(&buffs) {
                    Ok(_) => {
                        start_pos = end_pos;
                        continue;
                    }
                    Err(_) => {
                        let _ = self.conn.shutdown(std::net::Shutdown::Both);
                    }
                }
            }
            drop(lock_guard);
        }
    }

    pub fn write_string(&self, s: &str) {
        let mut vec = Vec::new();
        vec.extend_from_slice(s.as_bytes());
        self.write(vec, 1);
    }
    pub fn write_binary(&self, data: Vec<u8>) {
        self.write(data, 2);
    }
}
pub struct WebsocketEvent {
    ws: Websocket,
    pub message: WsMessage,
}

impl WebsocketEvent {
    pub fn get_conn(&self) -> &Websocket {
        &self.ws
    }
}

pub(crate) fn construct_http_event_for_websocket(
    stream: &mut TcpStream,
    method: &str,
    url: &str,
    http_version: &str,
    head_map: &HashMap<&str, &str>,
    connection_config: Arc<ConnectionData>,
) -> (bool, Option<Arc<dyn WsRouter + Send + Sync>>) {
    let conn = Rc::new(RefCell::new(stream));
    let request = Request {
        header_pair: head_map.clone(),
        url,
        method,
        version: http_version,
        body: BodyContent::None,
        conn_: Rc::clone(&conn),
        secret_key: Arc::clone(&connection_config.server_config.secret_key),
        ctx: RefCell::new(BTreeMap::new()),
    };
    let mut response = Response {
        header_pair: MultiMap::new(),
        version: http_version,
        method,
        //url,
        http_state: 200,
        body: BodyType::None,
        chunked: ResponseChunkMeta::new(connection_config.server_config.chunk_size),
        conn_: Rc::clone(&conn),
        range: ResponseRangeMeta::None,
        request_header: head_map.clone(),
        charset: None,
    };

    let ws_middleware_result = invoke_ws_middlewares(&connection_config, &request, &mut response);

    if !ws_middleware_result.0 {
        let mut stream = conn.borrow_mut();
        if !response.chunked.enable {
            match super::write_once(*stream, &mut response) {
                Ok(_) => {}
                Err(e) => {
                    if connection_config.server_config.open_log {
                        let now = super::get_current_date();
                        println!(
							"[{}] >>> error in write_once in websocket.rs; type: [{}], line: [{}], msg: [{}]",
							now,
							e.kind().to_string(),
							line!(),
							ToString::to_string(&e)
						);
                    }
                }
            }
        } else {
            // chunked transfer
            match super::write_chunk(*stream, &mut response) {
                Ok(_) => {}
                Err(e) => {
                    if connection_config.server_config.open_log {
                        let now = super::get_current_date();
                        println!(
							"[{}] >>> error in write_chunk in websocket.rs; type: [{}], line: [{}], msg: [{}]",
							now,
							e.kind().to_string(),
							line!(),
							ToString::to_string(&e)
						);
                    }
                }
            }
        }
        (false, None)
    } else {
        (true, ws_middleware_result.1)
    }
}

fn invoke_ws_middlewares_help(result: &WsRouterValue, req: &Request, res: &mut Response) -> bool {
    match &result.0 {
        Some(middlewares) => {
            // at least one middleware
            for middleware in middlewares {
                if !middleware.call(req, res) {
                    return false;
                }
            }
            return true;
        }
        None => true,
    }
}

fn invoke_ws_middlewares(
    connection_data: &ConnectionData,
    req: &Request,
    res: &mut Response,
) -> (bool, Option<Arc<dyn WsRouter + Send + Sync>>) {
    let url = req.url.split_once("?");
    let url = match url {
        Some((url, _)) => url,
        None => req.url,
    };
    let ws_router_map = &connection_data.ws_router_map;
    let not_found = connection_data
        .router_map
        .get("NEVER_FOUND_FOR_ALL")
        .unwrap();
    match ws_router_map.get(url) {
        Some(result) => {
            return (
                invoke_ws_middlewares_help(result, req, res),
                Some(Arc::clone(&result.1)),
            );
        }
        None => {
            not_found.1.call(req, res);
            return (false, None);
        }
    }
}

pub(crate) fn handle_websocket_connection(
    mut stream: TcpStream,
    header: HashMap<&str, &str>,
    ws_version: String,
    secret_key: String,
    ws_router: Arc<dyn WsRouter + Send + Sync>,
    connection_data: Arc<ConnectionData>,
) {
    //println!("handle_websocket_connection");
    let mut request_meta_header: HashMap<String, String> = HashMap::new();
    for (k, v) in header {
        request_meta_header.insert(k.to_string(), v.to_string());
    }
    let key = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", secret_key);
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();
    let result: &[u8] = hash.as_ref();
    let r = base64::encode(result);
    //println!("websocket: {r}");
    //let shared_tcp_connection = Arc::new(stream);
    let response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version:{}\r\nSec-WebSocket-Accept:{}\r\n\r\n",ws_version,r);
    match stream.write(response.as_bytes()) {
        Ok(_) => {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(
                connection_data.server_config.ws_read_timeout as u64,
            )));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(
                connection_data.server_config.ws_write_timeout as u64,
            )));
            switch_to_websocket(Arc::new(stream), ws_router, connection_data);
        }
        Err(_) => {}
    }
}

fn read_ws_data(
    reader: &mut BufReader<&TcpStream>,
    data_len: usize,
    data_buffs: &mut Vec<u8>,
) -> bool {
    let current_len = data_buffs.len();
    data_buffs.resize(current_len + data_len, b'\0');
    match reader.read(&mut data_buffs[current_len..]) {
        Ok(size) => {
            if size == 0 || size != data_len {
                return false;
            }
            true
        }
        Err(_) => false,
    }
}

fn decode_ws_data(mut raw_data: Vec<u8>, mask_key: [u8; 4]) -> Vec<u8> {
    let mut i = 0;
    let len = raw_data.len();
    while i < len {
        let j = i % 4;
        let r = raw_data[i] ^ mask_key[j];
        raw_data[i] = r;
        i += 1;
    }
    raw_data
}

fn switch_to_websocket(
    stream: Arc<TcpStream>,
    ws_router: Arc<dyn WsRouter + Send + Sync>,
    connection_data: Arc<ConnectionData>,
) {
    //println!("invoke switch_to_websocket");
    let fragment_size: usize = connection_data.server_config.ws_frame_size;
    let server_log_open = connection_data.server_config.open_log;
    let ws_handler = Websocket {
        conn: Arc::clone(&stream),
        write_mutex: Arc::new(Mutex::new(())),
        fragment_size: fragment_size,
    };
    let event = WebsocketEvent {
        ws: ws_handler.clone(),
        message: WsMessage::Open,
    };
    ws_router.call(event);
    let read_stream = Arc::clone(&stream);
    let (tx, rx) = mpsc::channel::<WebsocketEvent>();
    let _write_thread = thread::spawn(move || loop {
        match rx.recv() {
            Ok(event) => {
                let is_close = if let WsMessage::Close = event.message {
                    true
                } else {
                    false
                };
                ws_router.call(event);
                if is_close {
                    break;
                }
            }
            Err(e) => {
                if server_log_open {
                    let now = super::get_current_date();
                    println!(
						"[{}] >>> error in websocket write thread in websocket.rs; type: [RecvError], line: [{}], msg: [{}]",
						now,
						line!(),
						ToString::to_string(&e)
					);
                }
                break;
            }
        }
    });
    let _read_thread = thread::spawn(move || {
        let inner = read_stream.as_ref();
        let sender = tx;
        let mut reader = BufReader::new(inner);
        'Restart: loop {
            let mut data_buffs = Vec::new();
            let mut opcode = 0;
            let mut first_entry = true;
            'ReadFrame: loop {
                let mut buff = [b'\0'; 2];
                match reader.read(&mut buff) {
                    Ok(size) => {
                        if size == 0 {
                            break 'Restart;
                        }
                        let first_byte = buff[0];
                        let fin = (first_byte >> 7) & 1; // 1是最后一个包或完整的包, 0是分包
                        if first_entry {
                            opcode = first_byte & 0b00001111u8; //如果是分片传输，只记录首次的frame中的opcode
                            first_entry = false;
                        }
                        if size == 2 {
                            let second_byte = buff[1];
                            let mask = (second_byte >> 7) & 1;
                            if mask != 1 {
                                break 'Restart;
                            }
                            if opcode == 8 {
                                // //关闭连接
                                //构造close 通知
                                break 'Restart;
                            }
                            if opcode == 9 {
                                //ping
                                // 构造pong消息
                                ws_handler.write(Vec::new(), 10);
                                continue 'Restart;
                            }
                            if opcode == 10 {
                                //pong
                                // 客户端回应pong消息
                                continue 'Restart;
                            }
                            // 其他情况的opcode是消息体
                            let payload = second_byte & 0b01111111u8;
                            let data_len = if payload <= 125 {
                                // 就是data的实际大小
                                payload as usize
                            } else if payload == 126 {
                                // 后两个字节表示长度
                                let mut two_bytes = [b'\0'; 2];
                                match reader.read(&mut two_bytes) {
                                    Ok(size) => {
                                        if size == 0 || size != 2 {
                                            break 'Restart;
                                        }
                                        let endian = [
                                            b'\0',
                                            b'\0',
                                            b'\0',
                                            b'\0',
                                            b'\0',
                                            b'\0',
                                            two_bytes[0],
                                            two_bytes[1],
                                        ];
                                        usize::from_be_bytes(endian)
                                    }
                                    Err(e) => {
                                        if server_log_open {
                                            let now = super::get_current_date();
                                            println!(
												"[{}] >>> error in websocket read thread in websocket.rs; type: [{}], line: [{}], msg: [{}]",
												now,
												e.kind().to_string(),
												line!(),
												ToString::to_string(&e)
											);
                                        }
                                        break 'Restart;
                                    }
                                }
                            } else if payload == 127 {
                                // 后 8个字节表示长度
                                let mut eight_bytes = [b'\0'; 8];
                                match reader.read(&mut eight_bytes) {
                                    Ok(size) => {
                                        if size == 0 || size != 8 {
                                            break 'Restart;
                                        }
                                        usize::from_be_bytes(eight_bytes)
                                    }
                                    Err(e) => {
                                        if server_log_open {
                                            let now = super::get_current_date();
                                            println!(
												"[{}] >>> error in websocket read thread in websocket.rs; type: [{}], line: [{}], msg: [{}]",
												now,
												e.kind().to_string(),
												line!(),
												ToString::to_string(&e)
											);
                                        }
                                        break 'Restart;
                                    }
                                }
                            } else {
                                // payload 无效值
                                break 'Restart;
                            }; // data_len end

                            // 读取 Masking-key， 4个字节
                            let mut mask_key_buffs = [b'\0'; 4];
                            match reader.read(&mut mask_key_buffs) {
                                Ok(size) => {
                                    if size == 0 || size != 4 {
                                        break 'Restart;
                                    }
                                    // read data part;
                                    let r = read_ws_data(&mut reader, data_len, &mut data_buffs);
                                    if r == false {
                                        break 'Restart;
                                    } else {
                                        if fin == 1 {
                                            // 构造消息事件
                                            let event = WebsocketEvent {
                                                ws: ws_handler.clone(),
                                                message: WsMessage::Message(
                                                    decode_ws_data(data_buffs, mask_key_buffs),
                                                    opcode,
                                                ),
                                            };
                                            //println!("{:?}", event.message);
                                            match sender.send(event) {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    if server_log_open {
                                                        let now = super::get_current_date();
                                                        println!(
															"[{}] >>> error in websocket read thread in websocket.rs; type: [SendError], line: [{}], msg: [{}]",
															now,
															line!(),
															ToString::to_string(&e)
														);
                                                    }
                                                    break 'Restart; // 发送消息错误，关闭当前线程
                                                }
                                            }
                                            continue 'Restart; // 读完完整消息体，重新初始状态等待下一次消息
                                        } else {
                                            continue 'ReadFrame; //非完整消息，继续循环ReadFrame块功能
                                        }
                                    }
                                }
                                Err(e) => {
                                    if server_log_open {
                                        let now = super::get_current_date();
                                        println!(
											"[{}] >>> error in websocket read thread in websocket.rs; type: [{}], line: [{}], msg: [{}]",
											now,
											e.kind().to_string(),
											line!(),
											ToString::to_string(&e)
										);
                                    }
                                    break 'Restart;
                                }
                            }
                        } else {
                            break 'Restart;
                        }
                    }
                    Err(e) => {
                        if server_log_open {
                            let now = super::get_current_date();
                            println!(
								"[{}] >>> error in websocket write thread in websocket.rs; type: [{}], line: [{}], msg: [{}]",
								now,
								e.kind().to_string(),
								line!(),
								ToString::to_string(&e)
							);
                        }
                        break 'Restart;
                    }
                };
            }
        }
        let event = WebsocketEvent {
            ws: ws_handler.clone(),
            message: WsMessage::Close,
        };
        match sender.send(event) {
            Ok(_) => {}
            Err(e) => {
                if server_log_open {
                    let now = super::get_current_date();
                    println!(
						"[{}] >>> error in websocket read thread in websocket.rs; type: [SendError], line: [{}], msg: [{}]",
						now,
						line!(),
						ToString::to_string(&e)
					);
                }
            }
        }
    });
}
