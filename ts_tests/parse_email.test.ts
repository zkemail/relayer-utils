import { expect, test, describe } from "bun:test";

import { parseEmail } from "../pkg/relayer_utils";
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
});
