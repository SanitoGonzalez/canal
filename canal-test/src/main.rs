use std::net::UdpSocket;
use std::io::Result;

fn main() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:30001")?;
    socket.connect("127.0.0.1:30000")?;
    
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsString;
        use nix::sys::socket::{setsockopt, sockopt::BindToDevice};
        use std::os::unix::io::AsRawFd;
        
        // let sock_fd = socket.as_raw_fd();
        let interface = OsString::from("test0");
        setsockopt(&socket, BindToDevice, &interface)?;

        println!("Bound to test0");
    }

    // let message = b"Hello from test";
    socket.send(&[7, 8, 9])?;
    
    // let mut buf= [0; 10];
    // socket.recv(buf)

    Ok(())
}
