from DirDetective import DirectoryWatcher


powershell_script_path = "Powershell/CurrentDirectory.ps1"
dataset_md5_path = 'HashsDataset/merged_data.csv'
directory_watcher = DirectoryWatcher(powershell_script_path, dataset_md5_path)
directory_watcher.watch_directory()