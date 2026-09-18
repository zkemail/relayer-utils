import { expect, test, describe } from "bun:test";

import { parseEmail, parseEmailUnverified } from "../pkg/relayer_utils";
import airbnbEmail from "./airbnb_eml";
import { initOnce } from "./setup";

describe("Parse email test suite", async () => {
  await initOnce();

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
  
  test("Should parse valid email without pubkey", () => {
    console.log("parsing now");
    const parsedEmail = parseEmailUnverified(airbnbEmail);
    console.log("parsedEmail: ", parsedEmail);
    expect(parsedEmail).not.toBeUndefined();
  });
  
  test("Should throw a js error on invalid email without pubkey", () => {
    try {
      parseEmailUnverified("Invalid email");
    } catch (err) {
      console.log("err: ", err);
      expect(err).not.toBeUndefined();
      return;
    }
    throw new Error("Parsed invalid email");
  });
});
