# gRPC-Web Protobuf Editor for Burp Suite

A Burp Suite message editor tab for inspecting and editing protobuf payloads carried in gRPC-Web requests and responses. It decodes protobuf wire data without requiring a `.proto` schema and rebuilds the gRPC-Web frame when the message is edited.

## Features

- Adds a `gRPC-Web` tab to Burp message editors, including Proxy and Repeater.
- Handles `application/grpc-web+proto`, `application/grpc-web-text`, and `application/grpc-web+text` content types.
- Displays protobuf fields as an editable text tree, including varints, fixed-width values, strings, bytes, and heuristically detected nested messages.
- Preserves frame flags and trailer bytes, and recalculates the HTTP body length when rebuilding a message.
- Does not require protobuf schemas or third-party Python packages.

## Requirements

- Burp Suite with support for extensions using the legacy Extender API.
- Jython 2.7 standalone JAR configured in Burp Suite.

This extension uses Burp's legacy Extender API (`IBurpExtender`, `IMessageEditorTabFactory`, and `IMessageEditorTab`), rather than the newer Montoya API.

## Installation

1. Download `grpc_web_editor.py` from this repository.
2. In Burp Suite, open **Extensions** and then **Options**.
3. Set the Python environment to the Jython 2.7 standalone JAR.
4. Under **Installed**, choose **Add**.
5. Set the extension type to **Python**, select `grpc_web_editor.py`, and confirm.
6. Open a message whose `Content-Type` is supported and choose the `gRPC-Web` editor tab.

## Editing

The editor renders each data frame as protobuf-style text. Field numbers and wire-level types are shown; without a `.proto` schema, the extension cannot determine application-level field names or reliably distinguish strings, bytes, and nested messages. Nested-message detection is heuristic.

Edit the displayed fields, then switch tabs or send the message. Burp rebuilds the frame payload and HTTP body length. Trailer frames are displayed as bytes; edit their `trailer-bytes` hexadecimal value to change them. If a data frame cannot be decoded, its `raw-bytes` value is available for round-tripping or replacement.

The extension also enables its tab for `application/grpc` content types, but its decoder expects gRPC-Web-style five-byte frame headers. Standard gRPC HTTP/2 traffic may not use that body representation, so verify the displayed frames before editing.

- The extension is intended for authorized security testing and may not correctly interpret every gRPC or gRPC-Web implementation detail.
