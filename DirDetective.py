import subprocess
import os
import time
from win10toast import ToastNotifier
from HashFinder import HashFinder


class DirectoryWatcher:
    def __init__(self, powershell_script_path, dataset_md5_path):
        self.powershell_script_path = powershell_script_path
        self.hash_finder = HashFinder(dataset_md5_path)
        self.previous_paths = None

    def show_notification(self, title, message):
        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=10)

    def get_current_directory_paths(self):
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", self.powershell_script_path],
            stdout=subprocess.PIPE,
            text=True,
            shell=True
        )
        directory_paths = result.stdout.strip().split('\n')
        filtered_paths = [path for path in directory_paths if path.startswith("Directory Path")]
        extracted_paths = [path.split(": ", 1)[1] for path in filtered_paths]
        return extracted_paths

    def process_directory(self, path):
        extension = 'exe'
        files = [file for file in os.listdir(path) if file.endswith(f".{extension}")]
        print(f"EXEs in {path}:")
        for file in files:
            full_path = os.path.join(path, file)
            hash_value = self.hash_finder.get_file_hash(full_path)
            print("\t", file, "\t")
            is_malware = self.hash_finder.find_hash_in_dataset(hash_value)
            if is_malware:
                os.remove(full_path)
                self.show_notification(f"Malware Found {file}", f"{file} is Classified as Malware and Deleted\nPath:{full_path}")

            #print("\t", hash_value)
            self.previous_paths = [path]

    def watch_directory(self):
        while True:
            extracted_paths = self.get_current_directory_paths()

            if extracted_paths != self.previous_paths:
                for path in extracted_paths:
                    self.process_directory(path)

            time.sleep(2)


# Example usage:
powershell_script_path = "Powershell/CurrentDirectory.ps1"
dataset_md5_path = 'HashsDataset/merged_data.csv'
directory_watcher = DirectoryWatcher(powershell_script_path, dataset_md5_path)
directory_watcher.watch_directory()
