import { describe, expect, it } from "vitest";
import { PrivyPasskeyProvider } from "../src/index.js";

describe("PrivyPasskeyProvider", () => {
  it("initializes with configuration and sets default properties", () => {
    const provider = new PrivyPasskeyProvider({ appId: "cl_test_app_123" });
    expect(provider.id).toBe("privy");
    expect(provider.name).toContain("Privy Passkey");
    expect(provider.appId).toBe("cl_test_app_123");
  });

  it("updates app ID dynamically", () => {
    const provider = new PrivyPasskeyProvider();
    expect(provider.appId).toBeUndefined();
    provider.setAppId("cl_monad_mera_456");
    expect(provider.appId).toBe("cl_monad_mera_456");
  });

  it("registers a passkey in headless sandbox mode and creates a Privy user with DID", async () => {
    const provider = new PrivyPasskeyProvider();
    const wallet = "0x1111111111111111111111111111111111111111";

    const result = await provider.registerWithResponse({
      wallet,
      challenge: "test_challenge_bytes_123",
      userHandle: "test_user_handle",
      displayName: "Monad Trader",
      rpId: "localhost",
      rpName: "Homomorphic Biometric Passkeys",
    });

    expect(result.credential).toBeDefined();
    expect(result.credential.credentialId).toBeTruthy();
    expect(result.credential.spkiBase64Url).toBeTruthy();
    expect(result.credential.publicKeyHex.startsWith("0x")).toBe(true);

    // Verify Privy User DID format: did:privy:...
    expect(result.user).toBeDefined();
    expect(result.user.id.startsWith("did:privy:")).toBe(true);
    expect(result.user.walletAddress).toBe(wallet);

    // Verify raw WebAuthn response is present for gateway verification
    expect(result.rawResponse).toBeDefined();
    expect(result.rawResponse.credentialId).toBe(result.credential.credentialId);
    expect(result.rawResponse.clientDataJSON).toBeTruthy();
    expect(result.rawResponse.attestationObject).toBeTruthy();

    // Verify currentUser is cached
    expect(provider.getUser()?.id).toBe(result.user.id);
  });

  it("produces an assertion with hardware-backed signatures", async () => {
    const provider = new PrivyPasskeyProvider();
    const assertion = await provider.authenticate({
      challenge: "monad_userop_intent_challenge",
      credentialId: "cred_123",
      rpId: "localhost",
    });

    expect(assertion).toBeDefined();
    expect(assertion.clientDataJSON).toBeTruthy();
    expect(assertion.authenticatorData).toBeTruthy();
    expect(assertion.signature).toBeTruthy();
  });

  it("clears cached session on logout", async () => {
    const provider = new PrivyPasskeyProvider();
    await provider.registerWithResponse({
      wallet: "0x2222222222222222222222222222222222222222",
      challenge: "challenge_abc",
      userHandle: "handle_abc",
      displayName: "User ABC",
      rpId: "localhost",
      rpName: "Homomorphic Biometric Passkeys",
    });

    expect(provider.getUser()).not.toBeNull();
    provider.logout();
    expect(provider.getUser()).toBeNull();
  });
});
