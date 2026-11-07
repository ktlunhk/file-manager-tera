It is a web file manager which can connect to Tera Cloud Storage for normal file operation.
## Folder download
- Folder rows now have a Download button (and a Download entry in the ⋮ menu). The folder is copied from TeraBox into a temporary
  local folder, zipped and sent as `<folder>.zip`; the temporary files are removed afterwards.
- Same limits as ZIP creation: 1000 items, 20 folder levels, 256 MiB in total (see `mega_archive_stage_item`).
- While a folder ZIP is being prepared, the shared "Processing" overlay (with elapsed timer) is shown. The ZIP is requested through a
  hidden iframe; the server sets a `fileDownload=true` cookie when the file starts streaming, which closes the overlay. If the
  iframe loads a normal page instead, the overlay closes and the error notice is shown. Single files use the plain POST download.
- **Download selected items**: when one or more items are selected, a Download action appears in the mobile selection menu, the desktop
  selection bar and the bottom action grid. One selected file is sent as it is; a folder or several items are sent as one ZIP
  (same limits as ZIP creation). Folder download and multi-select download share `mega_stream_zip_download()` on the server and
  `megaOperationManager.download()` on the client.
