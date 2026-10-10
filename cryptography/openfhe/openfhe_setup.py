"""OpenFHE Setup and Testing Script"""

try:
    from openfhe import *
    import numpy as np
    OPENFHE_AVAILABLE = True
except ImportError:
    OPENFHE_AVAILABLE = False
    import numpy as np
    print("⚠️  OpenFHE not available. This script requires openfhe-python to run.")



def setup_ckks_context():
    """Initialize CKKS context with specified parameters."""
    print("Setting up CKKS context...")

    # Create parameter object
    parameters = CCParamsCKKSRNS()

    # Set parameters as specified
    parameters.SetMultiplicativeDepth(10)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(8192)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_128_classic)

    # Generate crypto context
    context = GenCryptoContext(parameters)

    # Enable required features
    context.Enable(PKESchemeFeature.PKE)
    context.Enable(PKESchemeFeature.KEYSWITCH)
    context.Enable(PKESchemeFeature.LEVELEDSHE)

    print("CKKS context initialized successfully")
    return context


def generate_keypair(context):
    """Generate public and private keypair."""
    print("Generating keypair...")
    keypair = context.KeyGen()
    print("Keypair generated successfully")
    return keypair


def test_encryption_decryption(context, keypair):
    """Test encryption and decryption of a float vector."""
    print("Testing encryption/decryption...")

    # Test vector
    test_vector = [1.0, 2.5, 3.7, 4.2]
    print(f"Original vector: {test_vector}")

    # Create plaintext
    plaintext = context.MakeCKKSPackedPlaintext(test_vector)

    # Encrypt
    ciphertext = context.Encrypt(keypair.publicKey, plaintext)
    print("Vector encrypted successfully")

    # Decrypt
    decrypted_plaintext = context.Decrypt(keypair.secretKey, ciphertext)
    decrypted_plaintext.SetLength(len(test_vector))

    # Get decrypted values
    decrypted_vector = decrypted_plaintext.GetRealPackedValue()
    print(f"Decrypted vector: {decrypted_vector}")

    # Validate
    tolerance = 1e-6
    for i, (orig, dec) in enumerate(zip(test_vector, decrypted_vector)):
        if abs(orig - dec) > tolerance:
            print(f"ERROR: Value at index {i} differs by {abs(orig - dec)}")
            return False

    print("Encryption/decryption test PASSED")
    return True


def test_homomorphic_addition(context, keypair):
    """Test homomorphic addition of two encrypted vectors."""
    print("Testing homomorphic addition...")

    # Input vectors
    v1 = [1.0, 2.0, 3.0]
    v2 = [4.0, 5.0, 6.0]
    expected = [5.0, 7.0, 9.0]

    print(f"v1: {v1}")
    print(f"v2: {v2}")
    print(f"Expected result: {expected}")

    # Create plaintexts
    p1 = context.MakeCKKSPackedPlaintext(v1)
    p2 = context.MakeCKKSPackedPlaintext(v2)

    # Encrypt
    c1 = context.Encrypt(keypair.publicKey, p1)
    c2 = context.Encrypt(keypair.publicKey, p2)

    # Homomorphic addition
    c_result = context.EvalAdd(c1, c2)
    print("Homomorphic addition performed")

    # Decrypt result
    p_result = context.Decrypt(keypair.secretKey, c_result)
    p_result.SetLength(len(expected))
    result_vector = p_result.GetRealPackedValue()

    print(f"Decrypted result: {result_vector}")

    # Validate
    tolerance = 1e-6
    for i, (exp, res) in enumerate(zip(expected, result_vector)):
        if abs(exp - res) > tolerance:
            print(f"ERROR: Result at index {i} differs by {abs(exp - res)}")
            return False

    print("Homomorphic addition test PASSED")
    return True


def print_context_parameters(context):
    """Print context parameters."""
    print("\nContext Parameters:")
    print(f"Cyclotomic Order: {context.GetCyclotomicOrder()}")
    print(f"Modulus: {context.GetModulus()}")
    print(f"Scaling Factor (Real): {context.GetScalingFactorReal()}")


def export_keys(keypair):
    """Export keypair to files."""
    print("\nExporting keys to files...")

    # Export private key
    keypair.secretKey.SerializeToFile("private_key.bin", "bin")
    print("Private key exported to private_key.bin")

    # Export public key
    keypair.publicKey.SerializeToFile("public_key.bin", "bin")
    print("Public key exported to public_key.bin")

    # Export evaluation keys if available
    try:
        if hasattr(keypair, 'evalKey'):
            keypair.evalKey.SerializeToFile("eval_key.bin", "bin")
            print("Evaluation key exported to eval_key.bin")
    except:
        print("No evaluation keys to export")


def main():
    """Main function to run all tests."""
    if not OPENFHE_AVAILABLE:
        print("❌ Cannot run tests: OpenFHE is not installed")
        print("To install OpenFHE, follow: https://github.com/openfheorg/openfhe-python")
        return 1
    
    print("=== OpenFHE CKKS Setup and Testing ===\n")


    try:
        # Setup
        context = setup_ckks_context()
        keypair = generate_keypair(context)

        # Tests
        test_encryption_decryption(context, keypair)
        print()
        test_homomorphic_addition(context, keypair)

        # Print parameters
        print_context_parameters(context)

        # Export keys
        export_keys(keypair)

        print("\n=== All tests completed successfully! ===")

    except Exception as e:
        print(f"ERROR: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
