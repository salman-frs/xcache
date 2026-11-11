use std::time::{Duration, Instant};

use crate::support::{Workspace, assert_outcome};

#[test]
fn network_access_is_not_cached() {
    let ws = Workspace::new();
    let script =
        "import socket\ns = socket.socket()\ns.settimeout(0.2)\ntry: s.connect(('192.0.2.1', 9))\nexcept OSError: pass";
    let run = ws.run(&["python3", "-c", script]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("network access to 192.0.2.1:9"), "{}", run.reasons());
}

#[test]
fn a_socket_path_with_no_service_behind_it_is_an_input() {
    let ws = Workspace::new();
    let script = "import socket\ns = socket.socket(socket.AF_UNIX)\ntry: s.connect('service.sock')\nexcept OSError: print('no service')";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");

    let _service = std::os::unix::net::UnixListener::bind(ws.path("service.sock")).unwrap();
    let run = ws.run(&["python3", "-c", script]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("service.sock"), "{}", run.reasons());
}

#[test]
fn a_socket_it_binds_renames_and_connects_to_is_its_own() {
    let ws = Workspace::new();
    let script = "import os, socket\nserver = socket.socket(socket.AF_UNIX)\nserver.bind('agent.tmp')\nos.chmod('agent.tmp', 0o600)\nos.rename('agent.tmp', 'agent')\nserver.listen()\nclient = socket.socket(socket.AF_UNIX)\nclient.connect('agent')\nos.unlink('agent')";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
}

#[test]
fn many_datagrams_to_its_own_sockets_stay_fast() {
    let ws = Workspace::new();
    let script = "import resource, socket\nsoft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)\nresource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))\nsockets = []\nfor _ in range(2500):\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n    s.bind(('127.0.0.1', 0 if not sockets else sockets[0].getsockname()[1]))\n    sockets.append(s)\nfor s in sockets:\n    s.sendto(b'x', sockets[0].getsockname())";
    let started = Instant::now();
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
}

#[test]
fn an_unused_loopback_port_is_an_input() {
    let ws = Workspace::new();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let script = format!(
        "import socket\nu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nu.connect(('127.0.0.1', {udp}))\n\
         t = socket.socket()\ntry: t.connect(('127.0.0.1', {tcp}))\nexcept OSError: pass"
    );
    assert_outcome(&ws.run(&["python3", "-c", &script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", &script]), "hit");

    let _service = std::net::UdpSocket::bind(("127.0.0.1", udp)).unwrap();
    let run = ws.run(&["python3", "-c", &script]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains(&format!("port {udp}")), "{}", run.reasons());
}

#[test]
fn a_socket_file_nobody_listens_on_is_not_cached() {
    let ws = Workspace::new();
    drop(std::os::unix::net::UnixListener::bind(ws.path("stale.sock")).unwrap());
    let script = "import socket\ns = socket.socket(socket.AF_UNIX)\ntry: s.connect('stale.sock')\nexcept OSError: pass";
    assert_outcome(&ws.run(&["python3", "-c", script]), "not_cached");
}

#[test]
fn a_link_it_makes_to_another_service_is_not_its_own() {
    let ws = Workspace::new();
    let _service = std::os::unix::net::UnixListener::bind(ws.path("service.sock")).unwrap();
    let script = "import os, socket\nos.symlink('service.sock', 'mine.sock')\ns = socket.socket(socket.AF_UNIX)\ns.connect('mine.sock')";
    assert_outcome(&ws.run(&["python3", "-c", script]), "not_cached");
}

#[test]
fn a_service_on_another_loopback_address_does_not_stand_for_this_one() {
    let ws = Workspace::new();
    let elsewhere = std::net::TcpListener::bind("127.0.0.2:0").unwrap();
    let port = elsewhere.local_addr().unwrap().port();
    let script = format!(
        "import socket\ntry: socket.create_connection(('127.0.0.1', {port}))\nexcept OSError: print('refused')"
    );
    assert_outcome(&ws.run(&["python3", "-c", &script]), "miss");

    let _here = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let run = ws.run(&["python3", "-c", &script]);
    assert_outcome(&run, "not_cached");
}

#[test]
fn talking_to_its_own_local_server_is_cacheable() {
    let ws = Workspace::new();
    let script = "import socket\nserver = socket.create_server(('127.0.0.1', 0))\nclient = socket.create_connection(server.getsockname())\nprint('connected')";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
}

#[test]
fn talking_to_a_service_it_did_not_start_is_not_cached() {
    let ws = Workspace::new();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let script = format!("import socket\nsocket.create_connection(('127.0.0.1', {port}))");
    let run = ws.run(&["python3", "-c", &script]);
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains(&format!("port {port}")), "{}", run.reasons());

    let socket_path = ws.path("service.sock");
    let _unix = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let script = format!("import socket\ns = socket.socket(socket.AF_UNIX)\ns.connect('{}')", socket_path.display());
    assert_outcome(&ws.run(&["python3", "-c", &script]), "not_cached");
}

#[test]
fn accepting_a_connection_from_outside_is_not_cached() {
    let ws = Workspace::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let client = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let script = format!("import socket\ns = socket.create_server(('127.0.0.1', {port}))\ns.accept()");
    let run = ws.run(&["python3", "-c", &script]);
    client.join().unwrap();
    assert_outcome(&run, "not_cached");
    assert!(run.reasons().contains("accepted a connection"), "{}", run.reasons());
}

#[test]
fn accepting_its_own_client_is_cacheable() {
    let ws = Workspace::new();
    let script = "import socket\ns = socket.create_server(('127.0.0.1', 0))\nc = socket.create_connection(s.getsockname())\ns.accept()";
    assert_outcome(&ws.run(&["python3", "-c", script]), "miss");
    assert_outcome(&ws.run(&["python3", "-c", script]), "hit");
}
