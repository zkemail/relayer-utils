import { expect, test, describe, it } from "bun:test";
import { publicKeyHash, init } from "../pkg";

const publicKeyHex =
  "cfb0520e4ad78c4adb0deb5e605162b6469349fc1fde9269b88d596ed9f3735c00c592317c982320874b987bcc38e8556ac544bdee169b66ae8fe639828ff5afb4f199017e3d8e675a077f21cd9e5c526c1866476e7ba74cd7bb16a1c3d93bc7bb1d576aedb4307c6b948d5b8c29f79307788d7a8ebf84585bf53994827c23a5";

// Convert hex string to Uint8Array (no reversal needed)
function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const publicKeyBytes = hexToBytes(publicKeyHex);

// The expected hash result from the Rust test
const expectedHash = "0x181ab950d973ee53838532ecb1b8b11528f6ea7ab08e2868fb3218464052f953";

describe("publicKeyHash", async () => {
  await init();
  it("should correctly hash the public key", async () => {
    const result = await publicKeyHash(publicKeyBytes);
    expect(result).toBe(expectedHash);
  });
});
