# FileDrop

A self-hosted LAN file-drop server for Windows. Upload files, paste notes, and share across your local network — no cloud, no accounts, no size cap beyond disk space.

![dark UI with drop zone and file list](.github/screenshot.png)

## Features

- Drag-and-drop or click-to-browse upload (up to 10 GB per file)
- Paste images from clipboard directly into the drop zone
- Save text notes without creating a file
- Folder navigation and inline preview (images, video, audio, PDF)
- Dark and light theme, persisted per browser
- Runs as a Windows background service (auto-starts on boot)
- CLI `send` command + Windows "Send To" shortcut integration
- Session cookie auth with 24-hour TTL

## Requirements

- Windows 10/11
- Go 1.21+ (to build from source)

## Setup

```sh
# 1. Build
go build -o filedrop.exe .

# 2. First-time configuration (sets upload dir, port, password)
filedrop.exe setup

# 3. Install and start the Windows service (run as Administrator)
filedrop.exe install
net start filedrop
```

Access from any device on your LAN:

```
http://<your-local-IP>:<port>
```

## Commands

| Command | Description |
|---|---|
| `setup` | First-time configuration — creates `config.json` |
| `install` | Register as a Windows service (requires admin) |
| `uninstall` | Remove the Windows service (requires admin) |
| `serve` | Run interactively without installing as a service |
| `send <file> ...` | Upload one or more files from the command line |

## Send To shortcut

Create a Windows "Send To" shortcut pointing at `filedrop.exe send` so you can right-click any file in Explorer → Send to → FileDrop.

1. Press `Win+R`, type `shell:sendto`, press Enter
2. Create a new shortcut with target: `C:\path\to\filedrop.exe send`

## Configuration

`config.json` is created by `setup` and lives next to the executable:

```json
{
  "password_hash": "...",
  "secret": "...",
  "upload_dir": "D:\\host",
  "port": 5743
}
```

Re-run `filedrop.exe setup` to change the password or upload directory.

## License

MIT
