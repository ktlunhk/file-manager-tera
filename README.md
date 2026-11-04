It is a web file manager which can connect to Tera Cloud Storage for normal file operation.
## Folder download
- Folder rows now have a Download button (and a Download entry in the ⋮ menu). The folder is copied from TeraBox into a temporary
  local folder, zipped and sent as `<folder>.zip`; the temporary files are removed afterwards.
- Same limits as ZIP creation: 1000 items, 20 folder levels, 256 MiB in total (see `mega_archive_stage_item`).
