# File Sharer

File Sharer is a LAN-only file transfer tool built with Tauri 2, TypeScript, and Rust. It is designed for quick drag-and-drop sharing between devices on the same local network.

中文：File Sharer 是一个仅限局域网使用的文件传输工具，基于 Tauri 2、TypeScript 和 Rust 构建，用于同一局域网内设备之间快速拖拽分享文件。

## Status

This project is early-stage software. Version `0.0.1` has only been tested on:

- Android arm64
- macOS on Apple Silicon M4

Windows, macOS Intel, other Android ABIs, and other environments have not been tested yet.

中文：当前版本仍处于早期阶段。`0.0.1` 只在 Android arm64 和 Apple Silicon M4 的 macOS 上测试过；Windows、Intel Mac、其他 Android 架构和其他环境尚未测试。

## Features

- LAN device discovery with UDP broadcast.
- Desktop drag overlay for macOS and Windows.
- Android mobile UI for device discovery, file picking, receiving, and transfer history.
- Default target device selection.
- Recent transfer history, capped at 100 records.
- Receive files into the system downloads area:
  - macOS / Windows: `Downloads/File Sharer`
  - Android: `Download/File Sharer`
- Encrypted file transfer protocol: `file-sharer.v2`.

中文：支持局域网设备发现、桌面拖拽悬浮窗、Android 移动端界面、默认目标设备、最近 100 条传输记录、下载目录保存，以及 `file-sharer.v2` 加密传输协议。

## Platform Targets

The planned release targets are:

- macOS universal package for Apple Silicon and Intel Macs.
- Windows x64 installer.
- Android arm64 APK.

Only Android arm64 and macOS Apple Silicon M4 have been manually tested.

中文：计划构建 macOS 通用包、Windows x64 安装包、Android arm64 APK；目前仅手动测试过 Android arm64 和 macOS M4。

## Development

Prerequisites:

- Node.js 20+
- Rust stable
- Tauri 2 prerequisites for your OS
- Android SDK / NDK for Android builds

Install dependencies:

```bash
npm install
```

Run the desktop app:

```bash
npm run app:dev
```

Run on Android:

```bash
npm run android:init
ANDROID_SERIAL=<device-id> npm run android:dev
```

中文：开发前需要安装 Node.js、Rust、Tauri 2 依赖；Android 构建还需要 Android SDK / NDK。

## Build

Desktop:

```bash
npm run app:build
```

Android arm64 APK:

```bash
npm run tauri -- android build --target aarch64 --apk --split-per-abi --ci
```

Android release signing uses GitHub Actions secrets:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Create `ANDROID_KEYSTORE_BASE64` from the local `.jks` file:

```bash
base64 -i /path/to/file-sharer-release.jks
```

Never commit `.jks`, `.keystore`, or `.p12` files to the repository.

中文：Android 发布包通过 GitHub Secrets 注入签名信息；不要把 `.jks`、`.keystore` 或 `.p12` 文件提交到仓库。

macOS universal package:

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run tauri -- build --target universal-apple-darwin
```

中文：桌面端使用 `npm run app:build` 构建；Android arm64 使用 Tauri Android build；macOS 通用包需要同时安装 Apple Silicon 和 Intel 的 Rust target。

## Release

GitHub Actions builds release artifacts when a tag like `v0.0.1` is pushed.

```bash
git tag v0.0.1
git push origin main --tags
```

中文：推送 `v0.0.1` 这类 tag 后，GitHub Actions 会自动构建并发布安装包。

## Security Scope

File Sharer is intended for trusted local networks only. The receiver rejects non-local addresses, and the transfer protocol encrypts file contents, but this project has not received an external security audit.

中文：本项目只面向可信局域网使用；接收端会拒绝非本地地址，传输内容会加密，但尚未经过外部安全审计。
