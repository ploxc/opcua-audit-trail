# macOS

The binaries are not signed or notarized, so macOS quarantines them after a
download. Remove that and make the file executable:

```sh
tar xzf opcua-audit-gateway-*-macos-arm64.tar.gz && cd opcua-audit-gateway-*
xattr -d com.apple.quarantine opcua-audit-gateway   # "No such xattr" is fine
chmod +x opcua-audit-gateway
./opcua-audit-gateway init && ./opcua-audit-gateway run
```

Use the `x86_64` archive on an Intel Mac.

`run` prints the first admin password in the terminal (see
[First login](../first-login.md)); the web UI is on http://127.0.0.1:8080.
`init` writes `config.toml` in the current directory; data and certificates
go next to it.
