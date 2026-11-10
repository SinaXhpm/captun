//! Per-OS "send through this interface" socket options. Binding the source
//! address alone is not enough everywhere: Linux and macOS will happily route
//! a bound socket out of the default interface.

use std::io;

use socket2::SockRef;

use crate::InterfaceBinding;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn bind_to_interface(socket: &SockRef<'_>, binding: &InterfaceBinding, _ipv4: bool) -> io::Result<()> {
    // SO_BINDTODEVICE needs CAP_NET_RAW, which the service has.
    socket.bind_device(Some(binding.name.as_bytes()))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn bind_to_interface(socket: &SockRef<'_>, binding: &InterfaceBinding, ipv4: bool) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(binding.index);
    if ipv4 { socket.bind_device_by_index_v4(index) } else { socket.bind_device_by_index_v6(index) }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn bind_to_interface(socket: &SockRef<'_>, binding: &InterfaceBinding, ipv4: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR, setsockopt,
    };

    // IP_UNICAST_IF takes the index in network byte order; the IPv6 variant
    // takes it in host order.
    let (level, name, value) = if ipv4 {
        (IPPROTO_IP, IP_UNICAST_IF, binding.index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, binding.index)
    };
    // SAFETY: the socket handle is valid for the lifetime of `socket`, and we
    // pass a pointer to a live u32 together with its exact size.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            name,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc == SOCKET_ERROR { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
pub(crate) fn bind_to_interface(_socket: &SockRef<'_>, _binding: &InterfaceBinding, _ipv4: bool) -> io::Result<()> {
    Ok(())
}
