use std::net::IpAddr;
use windows_sys::{
    Win32::{
        Foundation::FALSE,
        System::{
            Com::StringFromGUID2,
            Registry::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegOpenKeyExW, RegSetValueExW},
            Services::{
                CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
                SERVICE_CONTROL_PARAMCHANGE, SERVICE_PAUSE_CONTINUE, SERVICE_STATUS,
            },
        },
    },
    core::{BOOL, GUID},
};

/// The length of a GUID string looks like this: {c200e360-38c5-11ce-ae62-08002b2b79ef}, including the braces and null terminator.
const GUID_STRING_CAP: usize = 39;

pub fn set_dns_via_registry(guid: &GUID, dns_servers: &[IpAddr]) -> std::io::Result<()> {
    let mut guid_str = [0u16; GUID_STRING_CAP];
    let len = unsafe { StringFromGUID2(guid, guid_str.as_mut_ptr(), guid_str.len() as i32) };
    if len == 0 {
        return Err(std::io::Error::other("Failed to convert GUID to string"));
    }
    let guid_str = String::from_utf16_lossy(&guid_str[..(len as usize - 1)]);

    let (v4, v6) = split_by_family(dns_servers);

    let key_for =
        |stack: &str| format!("SYSTEM\\CurrentControlSet\\Services\\{stack}\\Parameters\\Interfaces\\{guid_str}");

    write_nameserver_registry(&key_for("Tcpip"), &dns_to_comma_separated(&v4))?;
    write_nameserver_registry(&key_for("Tcpip6"), &dns_to_comma_separated(&v6))?;

    notify_dnscache()?;
    if let Err(e) = flush_resolver_cache() {
        log::debug!("flush_resolver_cache failed: {e}");
    }

    Ok(())
}

crate::define_fn_dynamic_load!(
    DnsFlushResolverCacheDeclare,
    unsafe extern "system" fn() -> BOOL,
    DNS_FLUSH_RESOLVER_CACHE,
    DnsFlushResolverCache,
    "dnsapi.dll",
    "DnsFlushResolverCache"
);

fn flush_resolver_cache() -> std::io::Result<()> {
    let func = DnsFlushResolverCache()
        .ok_or("Failed to load function DnsFlushResolverCache")
        .map_err(std::io::Error::other)?;
    if unsafe { func() } == FALSE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_nameserver_registry(key_path: &str, name_server: &str) -> std::io::Result<()> {
    let key_wide = to_wide_null(key_path);
    let value_wide = to_wide_null("NameServer");
    let data_wide = to_wide_null(name_server);

    unsafe {
        let mut hkey = std::ptr::null_mut();
        let status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_wide.as_ptr(), 0, KEY_SET_VALUE, &mut hkey);
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }

        let byte_len = (data_wide.len() * 2) as u32;
        let status = RegSetValueExW(
            hkey,
            value_wide.as_ptr(),
            0,
            REG_SZ,
            data_wide.as_ptr().cast(),
            byte_len,
        );
        RegCloseKey(hkey);

        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

fn notify_dnscache() -> std::io::Result<()> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let svc = OpenServiceW(scm, to_wide_null("Dnscache").as_ptr(), SERVICE_PAUSE_CONTINUE);
        if svc.is_null() {
            let err = std::io::Error::last_os_error();
            CloseServiceHandle(scm);
            return Err(err);
        }

        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &mut status);
        let result = if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        };

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        result
    }
}

fn split_by_family(dns_servers: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    dns_servers.iter().partition(|ip| ip.is_ipv4())
}

fn dns_to_comma_separated(dns_servers: &[IpAddr]) -> String {
    dns_servers.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(",")
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
