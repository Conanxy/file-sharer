# THIS FILE IS AUTO-GENERATED. DO NOT MODIFY!!

# Copyright 2020-2023 Tauri Programme within The Commons Conservancy
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: MIT

-keep class dev.fang.file_sharer.* {
  native <methods>;
}

-keep class dev.fang.file_sharer.WryActivity {
  public <init>(...);

  void setWebView(dev.fang.file_sharer.RustWebView);
  java.lang.Class getAppClass(...);
  int getId();
  java.lang.String getVersion();
  int startActivity(...);
}

-keep class dev.fang.file_sharer.Ipc {
  public <init>(...);

  @android.webkit.JavascriptInterface public <methods>;
}

-keep class dev.fang.file_sharer.RustWebView {
  public <init>(...);

  void loadUrlMainThread(...);
  void loadHTMLMainThread(...);
  void evalScript(...);
}

-keep class dev.fang.file_sharer.RustWebChromeClient,dev.fang.file_sharer.RustWebViewClient {
  public <init>(...);
}
