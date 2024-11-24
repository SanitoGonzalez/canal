use std::net::UdpSocket;
use std::io::Result;

fn main() -> Result<()> {
    // let socket = UdpSocket::bind("192.168.200.1:30001")?;
    // socket.connect("192.168.200.1:30000")?;
    let socket = UdpSocket::bind("125.177.169.206:30001")?;
    socket.connect("125.177.169.206:30000")?;
    
    // #[cfg(target_os = "linux")]
    // {
    //     use std::ffi::OsString;
    //     use nix::sys::socket::{setsockopt, sockopt::BindToDevice};
    //     // use std::os::unix::io::AsRawFd;
        
    //     // let sock_fd = socket.as_raw_fd();
    //     let interface = OsString::from("dummy0");
    //     setsockopt(&socket, BindToDevice, &interface)?;

    //     println!("Bound to dummy0");
    // }

    // let message = b"Hello from test";
    socket.send(&[7, 8, 9])?;
    println!("Sent");
    
    // let mut buf= [0; 10];
    // socket.recv(buf)

    Ok(())
}
