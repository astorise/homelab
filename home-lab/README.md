# Tauri + Vanilla

This template should help get you started developing with Tauri in vanilla HTML, CSS and Javascript.

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)

## Windows requirements

Startup errors use the modern `TaskDialogIndirect` API when it is available (Windows Vista or newer). If the function is missing, the application falls back to `MessageBoxW`, so it can still display an error on older versions of Windows. Without this fallback, Windows Vista would be the minimum supported version.
