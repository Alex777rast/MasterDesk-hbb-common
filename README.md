# MasterDesk hbb_common

This repository is the public `hbb_common` submodule fork used by
[MasterDesk](https://github.com/Alex777rast/MasterDesk).

It preserves the upstream history from
[rustdesk/hbb_common](https://github.com/rustdesk/hbb_common) and contains the
MasterDesk network-routing and configuration changes required to reproduce
release builds.

Do not build this repository as a standalone application. Clone MasterDesk
with recursive submodules:

```powershell
git clone --recurse-submodules https://github.com/Alex777rast/MasterDesk.git
```

The code is distributed under GNU AGPL-3.0 as part of the modified RustDesk
work. MasterDesk is an independent modified project, not an official RustDesk
release.
