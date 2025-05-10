import argparse
import hashlib
import logging
import os
import sys
import json

try:
    from dsse.dsse import sign  # Assuming dsse library or similar
    HAS_DSSE = True
except ImportError:
    HAS_DSSE = False
    print("dsse library not found. Digital signature functionality will be disabled.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='SBOM Attestation Generator - Signs SBOMs using DSSE.')
    parser.add_argument('sbom_file', type=str, help='Path to the SBOM file.')
    parser.add_argument('private_key_file', type=str, help='Path to the private key file (PEM format).')
    parser.add_argument('output_attestation_file', type=str, help='Path to save the generated attestation file.')
    parser.add_argument('--algorithm', type=str, default='sha256', choices=['sha256', 'sha512'], help='Hashing algorithm to use (default: sha256)')
    parser.add_argument('--payload-type', type=str, default='application/vnd.in-toto+json', help='Payload type for the attestation (default: application/vnd.in-toto+json)')
    return parser


def calculate_sbom_hash(sbom_file, algorithm='sha256'):
    """
    Calculates the hash of the SBOM file.

    Args:
        sbom_file (str): Path to the SBOM file.
        algorithm (str): Hashing algorithm to use (default: sha256).

    Returns:
        str: The calculated hash value.
    """
    try:
        hasher = hashlib.new(algorithm)
        with open(sbom_file, 'rb') as f:
            while True:
                chunk = f.read(4096)  # Read in chunks for large files
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logging.error(f"SBOM file not found: {sbom_file}")
        raise
    except Exception as e:
        logging.error(f"Error calculating SBOM hash: {e}")
        raise


def create_attestation(sbom_hash, private_key_file, payload_type='application/vnd.in-toto+json'):
    """
    Creates a digital attestation for the SBOM hash using a private key.

    Args:
        sbom_hash (str): The hash of the SBOM.
        private_key_file (str): Path to the private key file.
        payload_type (str): The payload type for the attestation.

    Returns:
        dict: The attestation data structure, or None on error.
    """
    if not HAS_DSSE:
        logging.error("DSSE library is not available. Cannot create attestation.")
        return None

    try:
        with open(private_key_file, 'r') as f:
            private_key = f.read()

        payload = {
            'payloadType': payload_type,
            'payload': sbom_hash
        }

        # Sign the payload
        attestation = sign(payload, private_key)

        return attestation
    except FileNotFoundError:
        logging.error(f"Private key file not found: {private_key_file}")
        raise
    except Exception as e:
        logging.error(f"Error creating attestation: {e}")
        raise


def save_attestation(attestation, output_file):
    """
    Saves the attestation data to a JSON file.

    Args:
        attestation (dict): The attestation data.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(attestation, f, indent=2)
        logging.info(f"Attestation saved to: {output_file}")
    except Exception as e:
        logging.error(f"Error saving attestation: {e}")
        raise


def validate_input_paths(sbom_file, private_key_file):
    """
    Validates that the input file paths exist.

    Args:
        sbom_file (str): Path to the SBOM file.
        private_key_file (str): Path to the private key file.
    """
    if not os.path.exists(sbom_file):
        raise FileNotFoundError(f"SBOM file not found: {sbom_file}")
    if not os.path.exists(private_key_file):
        raise FileNotFoundError(f"Private key file not found: {private_key_file}")


def main():
    """
    Main function to execute the SBOM attestation generation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        validate_input_paths(args.sbom_file, args.private_key_file)

        # Calculate the SBOM hash
        sbom_hash = calculate_sbom_hash(args.sbom_file, args.algorithm)
        logging.info(f"SBOM hash: {sbom_hash}")

        # Create the attestation
        attestation = create_attestation(sbom_hash, args.private_key_file, args.payload_type)

        if attestation:
            # Save the attestation to a file
            save_attestation(attestation, args.output_attestation_file)
        else:
            logging.error("Attestation creation failed.")
            sys.exit(1)

    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Example Usage (Illustrative - assumes a working 'dsse' and proper files):
#
# Generate a key pair (for testing only - NEVER use these keys in production):
# openssl genrsa -out private.pem 2048
# openssl rsa -in private.pem -pubout -out public.pem
#
# Create a sample SBOM file (sbom.json):
# echo '{"name": "MyProject", "version": "1.0.0"}' > sbom.json
#
# Run the tool:
# python sbom_attestation_generator.py sbom.json private.pem attestation.json
#
# Example with sha512:
# python sbom_attestation_generator.py sbom.json private.pem attestation.json --algorithm sha512
#
# Example with a different payload type:
# python sbom_attestation_generator.py sbom.json private.pem attestation.json --payload-type application/spdx+json