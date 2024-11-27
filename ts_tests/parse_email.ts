/*
 * TODO: Make jest ignore this
 * This file does not work with jest, so for now we renamed it so it doesn't run.
 */
import { expect, test, describe } from "bun:test";

import init, { parseEmail } from "../pkg";
import airbnbEmail from "./airbnb_eml";

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
});
