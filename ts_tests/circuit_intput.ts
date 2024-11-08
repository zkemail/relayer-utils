import { expect, test, describe } from "bun:test";
// import init, { parseEmail } from "../pkg";
import { generateCircuitInputsWithDecomposedRegexesAndExternalInputs } from "../pkg/index.node";
import { readFile } from "fs/promises";

describe("generateCircuitInputsWithDecomposedRegexesAndExternalInputs test suite", async () => {
  const helloEml = await readFile("tests/fixtures/test.eml", "utf-8");
  console.log("got eml: ", helloEml);

  test("Should parse valid email", async () => {
    const decomposedRegexes = [
      {
        parts: [
          {
            is_public: true,
            regex_def: "Hi",
          },
          {
            is_public: true,
            regex_def: "!",
          },
        ],
        name: "hi",
        maxLength: 64,
        location: "body",
      },
    ];

    const params = {
      maxHeaderLength: 2816,
      maxBodyLength: 1024,
      ignoreBodyHashCheck: false,
      removeSoftLinesBreaks: true,
      // sha_precompute_selector
    };

    console.log("calling massive function");
    const inputs = await generateCircuitInputsWithDecomposedRegexesAndExternalInputs(
      helloEml,
      decomposedRegexes,
      [],
      params
    );
    console.log("inputs: ", inputs);
    // expect(parsedEmail).not.toBeUndefined();
  });
});
