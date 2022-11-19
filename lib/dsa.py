import hashlib
import os
from shutil import rmtree
from zipfile import ZipFile
from lib.rsa import RSA

class DSA:
    
    def __file_hash(file_path):
        """Generates a hash from given file

        Args:
            file_path (str): Path to a file.

        Returns:
            str: Hash of given file.
        """

        buffer_size = 4294967296
        file_hash = hashlib.sha3_512()

        with open(file_path, 'rb') as f:
            buffer = f.read(buffer_size)
            while len(buffer) > 0:
                file_hash.update(buffer)
                buffer = f.read(buffer_size)

        return file_hash.hexdigest()

    
    def __zip_files(files_paths, zip_path):
        """Zips files in files_paths into one zip

        Args:
            files_paths (list): List of paths to files to zip.
            zip_path (str): Path where to save generated zip.
        """

        with ZipFile(zip_path, 'w') as zip:
            for path in files_paths:
                zip.write(path, arcname=os.path.basename(path))


    @classmethod
    def sign(cls, to_sign_path, private_key, save_path='', delete_original=False):
        """Generates a zip with an encrypted sign file

        Generates a zip file in save_path location that contains the original file
        with a signature.sign file that contains hash of signed file encrypted with
        rsa private_key pair. After the signed zip is created, unzipped sign file is
        deleted. Original to_sign file can be deleted with delete_original argument.

        Args:
            to_sign_path (str): Path to a single file to be signed.
            private_key (touple): Touple of RSA private key pair
            save_path (str, optional): Where to save signed zip. If not set -> to_sign_path folder
            delete_original (bool, optional): If True -> del original to_sign file. Defaults to False.
        """

        # Check if path is file
        if not os.path.isfile(to_sign_path):
            raise Exception("ERROR: Can't sign a folder.")
        
        dir_path, file_name = os.path.split(os.path.abspath(to_sign_path))
        to_sign_path = os.path.join(dir_path, file_name)

        # Get hash from file and encrypt it
        file_hash = cls.__file_hash(to_sign_path)
        rsa = RSA()
        try:
            encryped_file_hash = rsa.encrypt(file_hash, private_key)
        except:
            raise Exception("ERROR: There was an error while encrypting the file hash.")

        # Create sign file with signature
        signature_path = os.path.join(dir_path, 'signature.sign')
        with open(signature_path, 'w+') as f:
            f.write(f"RSA_SHA3-512 {encryped_file_hash}")
        
        # Zip files together
        paths = [signature_path, to_sign_path]
        cls.__zip_files(paths, save_path)

        # Delete unzipped files
        os.remove(os.path.join(dir_path, 'signature.sign'))
        if delete_original:
            os.remove(os.path.join(dir_path, file_name))

    
    @classmethod
    def check(cls, zip_path, public_key, delete_zip=False):
        """Checks if signed file is valid or not

        Extracts given zip, checks encrypted signature, decrypts it and compares it to
        hash of the other file in the zip. Deletes unzipped files (can delete zip file
        too with delete_zip set to True) and returns True if hashes are equal else
        returns False.

        Args:
            zip_path (str): Path to signed zip.
            public_key (touple): Touple or RSA public key pair.
            delete_zip (bool, optional): If True -> delete zip. Defaults to False.

        Returns:
            bool: True if file is valid else False
        """

        dir_path, file_name = os.path.split(os.path.abspath(zip_path))

        # Check if path is to zip file
        if file_name.split('.')[-1] != 'zip':
            raise Exception(f"ERROR: {file_name} is not .zip file.")

        # Check and extract zip
        with ZipFile(zip_path, 'r') as zip:
            # Check zip content
            if 'signature.sign' not in zip.namelist() or len(zip.namelist()) > 2:
                raise Exception("ERROR: Wrong zip format (must be a single file with a signature file).")
            
            # Save signed file name for getting hash
            signed_file_name = [name for name in zip.namelist() if name != 'signature.sign'][0]
            
            # Obscure name of extract folder so no user files would be accidentaly deleted.
            extract_folder_path = os.path.join(dir_path, 'temp_dsa_82520735')
            # Extract valid zip
            zip.extractall(path=extract_folder_path)
        
        # Remove now unnecessary zip if want to
        if delete_zip:
            os.remove(os.path.abspath(zip_path))

        # Get file hash
        file_hash = cls.__file_hash(os.path.join(extract_folder_path, signed_file_name))

        # Get encrypted hash
        with open(os.path.join(extract_folder_path, 'signature.sign'), 'r') as f:
            encrypted_file_hash = f.read().replace('RSA_SHA3-512 ', '')
        
        # Remove unzipped folder
        rmtree(extract_folder_path)
        # os.remove(os.path.join(extract_folder_path, 'signature.sign'))
        # os.remove(os.path.join(extract_folder_path, signed_file_name))
        
        # Decrypt encrypted hash
        rsa = RSA()
        try:
            decrypted_file_hash = rsa.decrypt(encrypted_file_hash, public_key)
        except:
            raise Exception("ERROR: There was an error while decrypting the file hash. Perhaps a wrong key?")

        # Check if hashes are equal
        if file_hash == decrypted_file_hash:
            return True
        
        return False