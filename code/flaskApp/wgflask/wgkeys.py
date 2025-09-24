import subprocess

class WireGuardKeyGenerator:
    
    @staticmethod
    def generate_private_key():
        try:
            result = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Private key generation failed with error code: {e.returncode}")
            return None
        return result.stdout.strip()

    @staticmethod
    def generate_public_key(private_key):
        try:
            result = subprocess.run(["wg", "pubkey"], capture_output=True, text=True, input=private_key, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Public key generation failed with error code: {e.returncode}")
            return None
        return result.stdout.strip()

    @staticmethod
    def generate_key_pair():
        private_key = WireGuardKeyGenerator.generate_private_key()
        if private_key is None:
            return None, None
        public_key = WireGuardKeyGenerator.generate_public_key(private_key)
        return private_key, public_key

    @staticmethod
    def generate_preshared_key():
        try:
            result = subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Pre-shared key generation failed with error code: {e.returncode}")
            return None
        return result.stdout.strip()
