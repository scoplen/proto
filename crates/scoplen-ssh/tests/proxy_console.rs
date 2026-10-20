// SPDX-License-Identifier: Apache-2.0

#![cfg(windows)]
// A GUI test host exposes the console window that Windows otherwise creates for a console child.
#![windows_subsystem = "windows"]

use std::{io::Read, net::Shutdown};

use scoplen_ssh::{ProxyCommandTransport, Transport};

#[test]
fn proxy_command_console_child_has_no_window_from_gui_parent() {
    let script = "Add-Type -Name NativeConsole -Namespace Scoplen -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern IntPtr GetConsoleWindow();'; [Scoplen.NativeConsole]::GetConsoleWindow().ToInt64()";
    let mut transport = ProxyCommandTransport::spawn(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", script],
    )
    .expect("spawn console child");
    transport.shutdown(Shutdown::Write).expect("close stdin");
    let mut response = String::new();
    transport.read_to_string(&mut response).expect("read console window handle");
    assert_eq!(response.trim(), "0");
}
