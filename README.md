# rust-xfinal
A safe and performance web server framework that is written by Rust.

### Introduction
~This is the beginning of the aim to write a safe web server framework by Rust. For now, this repository has not provided complete and stable functions yet, as [xfinal](https://github.com/xmh0511/xfinal) has done, written by modern c++.~ The aim is to build up a simply used, performance, and safe web server framework.

### Advantages 
1. Since the advantages of Rust are that it is safe on memory and multiple threads, and it is a modern programming language that has almost no pieces baggage c++ has, the framework that is written based on Rust has no worry about the hard problems with memory and data race. Rust can guarantee the safety of these aspects. 

2. Moreover, Rust has the characteristics of zero-cost abstraction, as c++ has, hence the performance of the framework will be desired as you expect, rapid! 

3. Rust has a very convenient package manager: Cargo, which can make you feel free to use any third crate without being necessary to use CMake to manage these dependencies or even to write obscure rules that are ugly. 


### Features that have been supported
1. Register router.
2. Register middleware.
3. Query text-plain body, url-form data, and multipart-form data(include uploaded files).
4. Chunked transfer
5. Accept Range requests, which implies that rust-xfinal has supported to download file with the resume breakpoint.
6. View render based on tera
7. Support the resumable cookie(i.e the cookie can still be recognized after the server is restarted)
8. Support transfer user data from middlwares to eventual router

### Features that haven't been supported yet
1. Seems not to have

### Usage
> 1. HTTP "hello, world"
````rust
use http_server::{
    end_point, EndPoint, HttpServer, Request, Response, GET,
};
fn main(){
   let mut http_server = HttpServer::create(end_point!(0.0.0.0:8080), 10);
   http_server.route(GET, "/").reg(|req: &Request, res: &mut Response| {
       res.write_string("hello, world"); // default http status is 200, you can also specify it.
   });
   http_server.run();
}
````

> 2. Use middlewares
````rust
use http_server::{
    end_point, inject_middlewares, EndPoint, HttpServer, MiddleWare, Request, Response, GET,
};
fn main(){
   let mut http_server = HttpServer::create(end_point!(0.0.0.0:8080), 10);
   fn interrupt_second(req:& Request,res:&mut Response) ->bool{
        println!("invoke middleware2");
        match req.get_param("id") {
            Some(v) => {
                if v == "1"{
                    true
                }else{
                    res.write_string("invalid request, invalid id value").status(400);
                    false
                }
            },
            None => {
                res.write_string("invalid request, no id").status(400);
                false
            },
        }
   }
   let middlewares = inject_middlewares! {
      |req:& Request,res:&mut Response|->bool{
          println!("invoke middleware");
          true
      },interrupt_second //, middleware 3,..., so forth
   };
   
   http_server.route(GET, "/middle").reg_with_middlewares(
        middlewares,
        |req: &Request, res: &mut Response| {
            println!("invoke router");
            res.write_string("hello from router with middleware passed");
        },
   );
   http_server.run();
}
````

> 3. Query information from Request
````rust
http_server.route(GET, "/query").reg(|req: &Request, res: &mut Response| {
    let r:Option<&str> = req.get_query("id");
    let host = req.get_header("Host");
    let file = req.get_file("file");
    let version = req.get_version();
    let method = req.get_method();
    let headers = req.get_headers();
    let forms = req.get_queries();
    let get_all_files = req.get_files();
    let url = req.get_url();
    let id = req.get_param("id"); // /a?id=0
    res.write_string("ok").status(200);
});
````
> 4. Chunked transfer and/or Rangeable
>> Range function almost need to pair with HEAD
````rust
http_server.route([GET,HEAD], "/query").reg(|_req: &Request, res: &mut Response| {
    // file: res.write_file("./upload/test.mp4",200).chunked().enable_range();
   //string: res.write_string("abcdefg",200).chunked();
  // res.write_string("abcdefg",200).enable_range();
  // file: res.write_file("./upload/test.mp4",200).enable_range().chunked();
  // No sequence requirement, whatever combination as you go.
});
````
>5. Wildcard path
````rust
http_server.route(GET, "/wildcard/*").reg(|_req: &Request, res: &mut Response|{
      let s = format!("hello from {}", req.get_url());
      res.write_string(&s).status(200);
});
````
>6. view render
````rust
use rust_xfinal::{EndPoint,end_point,HttpServer,GET, Request,Response,tera};

fn render(ctx:&Request) -> tera::Result<String>{
	let mut context = tera::Context::new();
	context.insert("text",&ctx.get_url().to_string());
	let t = tera::Tera::new("template/**/*")?;  // customize your own tera whatever you want
	return t.render("test.html",&context);
}
fn main() {
	let mut server = HttpServer::create(end_point![0.0.0.0:8080], 10);
	server.route(GET, "/").reg(|req:&Request,res:& mut Response|{
		let mut context = tera::Context::new();
		context.insert("text", "abcdefg");
		res.render_view_once("./test.html", &context);
	});

	server.route(GET, "/custome").reg(|req:&Request,res:& mut Response|{
		res.render_view(render,req);
	});
	server.run();
}
````
>7. Cookie
````rust
use rust_xfinal::{cookie, end_point, tera, EndPoint, HttpServer, Request, Response, GET};
use cookie::Period;
fn main() {
	let mut server = HttpServer::create(end_point![0.0.0.0:8080], 10);
	server.route(GET, "/cookie").reg(|req:&Request,res:& mut Response|{
    	let mut cookie = cookie::Cookie::new(String::from("token"),req);
    	cookie.insert(String::from("login"), true);
    	cookie.set_path("/".to_string());
    	cookie.set_max_age(2.days().from_now());  // the cookie will be expired after 2 days  
    	res.write_string("ok").with_cookies(cookie);
    });

	server.route(GET, "/validate").reg(|req:&Request,res:& mut Response|{
    	let cookie = cookie::Cookie::new(String::from("token"),req);
    	let login:Option<bool> = cookie.get_data(String::from("login"));
    	let s = format!("{:?}",login);
    	res.write_string(&s);
    });

	server.route(GET, "/cookie").reg(|req:&Request,res:& mut Response|{
    	let mut cookie = cookie::Cookie::new(String::from("token"),req);
    	cookie.insert(String::from("login"), true);
    	cookie.set_path("/".to_string());
    	cookie.set_max_age(2.days().from_now());
		cookie.set_http_only(true);
		let mut cookie2 = cookie::Cookie::new(String::from("test"),req);
		cookie2.set_path("/".to_string());
		cookie2.insert(String::from("test"), "abc");
		cookie2.insert(String::from("age"), 18);
		cookie2.set_http_only(false);
    	res.write_string("ok").with_cookies([cookie,cookie2]);
    });

    server.route(GET, "/validate2").reg(|req:&Request,res:& mut Response|{
    	let cookie = cookie::Cookie::new(String::from("token"),req);
    	let login:Option<bool> = cookie.get_data(String::from("login"));
		let cookie2 = cookie::Cookie::new(String::from("test"),req);
		let test:Option<String> = cookie2.get_data("test".to_string());
		let age:Option<i32> = cookie2.get_data("age".to_string());
    	let s = format!("\"{:?}\",{:?},{:?}",login,test,age);
		res.add_header("content-type".to_string(), "text/plain; charset=UTF-8".to_string());
    	res.write_string(&s);
    });

}
````
> 8. Transfer user data between middlewares and the eventual router 
````rust
    use rust_xfinal::{JsonValue,inject_middlewares};
    fn interrupter(req: &Request, res: &mut Response) -> bool {
        match req.get_param("id") {
            Some(v) => {
                if v == "1" {
					let mut ctx = req.context().borrow_mut();
					ctx.insert("number".to_string(), JsonValue::Number(20.into()));
                    true
                } else {
                    res.write_string("invalid request, invalid id value")
                        .status(400);
                    false
                }
            }
            None => {
                res.write_string("invalid request, no id").status(400);
                false
            }
        }
    }
	server.route(GET, "/transfer").reg_with_middlewares(
        inject_middlewares![interrupter],
        |req: &Request, res: &mut Response| {
			let ctx = req.context().borrow_mut();
			let d = ctx.get(&"number".to_string());
			let s = format!("abc,{:?}",d);
			let method = req.get_method();
            res.write_string(&s);
        },
    );
````

