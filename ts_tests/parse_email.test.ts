import { parseEmail } from "../pkg/relayer_utils";

test("Should provide descriptive error for empty email", async () => {
    try {
        await parseEmail("");
        throw new Error("Should have failed");
    } catch (err) {
        expect(err.toString()).toContain("Invalid email: Email cannot be empty");
    }
});

test("Should provide descriptive error for invalid email format", async () => {
    try {
        await parseEmail("invalid-email-format");
        throw new Error("Should have failed");
    } catch (err) {
        expect(err.toString()).toContain("Invalid email: Email must contain @ symbol");
    }
});

test("Should provide descriptive error for malformed DKIM signature", async () => {
    try {
        await parseEmail("test@example.com\nDKIM-Signature: invalid");
        throw new Error("Should have failed");
    } catch (err) {
        expect(err.toString()).toContain("Failed to parse email: Invalid DKIM signature");
    }
});
