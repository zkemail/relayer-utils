/*
 * TODO: Make jest ignore this
 * This file does not work with jest, so for now we renamed it so it doesn't run.
 */
 // TODO: Can only run one test file at a time, since init() will colide
import { expect, test, describe } from "bun:test";

import { parseEmail, init } from "../pkg";
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
