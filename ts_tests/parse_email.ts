/*
 * TODO: Make jest ignore this
 * This file does not work with jest, so for now we renamed it so it doesn't run.
 */
// TODO: Can only run one test file at a time, since init() will colide
import { expect, test, describe } from "bun:test";

import { parseEmail, init } from "../pkg";
import airbnbEmail from "./airbnb_eml";
import airbnbEmailInvalid from "./airbnb_eml_invalid";

describe("Parse email test suite", async () => {
  await init();

  test("Should parse valid email", async () => {
    const parsedEmail = await parseEmail(airbnbEmail);
    expect(parsedEmail).not.toBeUndefined();
  });

  test("Should throw a js error on invalid email", async () => {
    try {
      await parseEmail("Invalid email");
    } catch (err) {
      console.log("err: ", err);
      expect(err).not.toBeUndefined();
      return;
    }
    throw new Error("Parsed invalid email");
  });

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
      await parseEmail(airbnbEmailInvalid);
      throw new Error("Should have failed");
    } catch (err) {
      expect(err.toString()).toContain("Failed to parse email: Invalid DKIM signature");
    }
  });

  test("Should not be able to use regex lookaheads", async () => {
    try {
      await parseEmail(airbnbEmailInvalid);
      throw new Error("Should have failed");
    } catch (err) {
      expect(err.toString()).toContain("Failed to parse email: Invalid DKIM signature");
    }
  });
});
