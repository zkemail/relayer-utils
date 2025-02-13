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
    console.log("publicKey: ", JSON.stringify(parsedEmail.publicKey));
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

  test("Should be able to pass public key", async () => {
    const publicKey = new Uint8Array([
      187, 253, 64, 73, 193, 204, 129, 152, 156, 189, 171, 157, 139, 125, 240, 66, 129, 91, 189,
      174, 39, 24, 60, 18, 54, 163, 143, 183, 251, 72, 64, 6, 100, 100, 241, 93, 53, 191, 34, 176,
      38, 176, 234, 185, 81, 105, 31, 113, 119, 179, 20, 151, 59, 8, 150, 85, 159, 78, 102, 50, 144,
      90, 196, 236, 191, 210, 112, 222, 119, 97, 121, 109, 128, 47, 203, 253, 157, 170, 91, 131,
      238, 91, 105, 94, 1, 35, 16, 235, 184, 214, 132, 22, 113, 243, 42, 60, 46, 244, 81, 117, 213,
      2, 250, 197, 243, 105, 42, 162, 158, 184, 125, 233, 101, 87, 64, 142, 14, 39, 219, 187, 15,
      78, 119, 249, 248, 59, 143, 179,
    ]);
    const parsedEmail = await parseEmail(airbnbEmail, publicKey);
    expect(new Uint8Array(parsedEmail.publicKey)).toEqual(publicKey);
  });
});
