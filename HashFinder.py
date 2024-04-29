import hashlib
import time
import pandas as pd


class HashFinder:
    def __init__(self, file_path):
        self.df = pd.read_csv(file_path)
        self.num_rows = self.df.shape[0]
        print(f"The dataset has {self.num_rows} rows.")

    def find_hash_in_dataset(self, hash_value):
        start_time = time.time()

        hash_set = set(self.df.values.flatten())
        x = 0
        if hash_value in hash_set:
            x=1
        else:
            x= 0
        return x

        """elapsed_time = time.time() - start_time
        print(f"Time taken: {elapsed_time} seconds")"""

    def get_file_hash(self, file_path):
        hasher = hashlib.md5()

        try:
            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            #print(f"The hash of {file_path} is: {file_hash}")
            return file_hash
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
"""
sample = "sample.exe"
hash_finder = HashFinder("HashsDataset\merged_data.csv")
hash_value = hash_finder.get_file_hash(sample)
print (hash_value)
print(hash_finder.find_hash_in_dataset(hash_value))"""