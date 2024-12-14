// TODO: Can only run one test file at a time, since init() will colide
import { expect, test, describe } from "bun:test";
import { generateCircuitInputsWithDecomposedRegexesAndExternalInputs, init } from "../pkg";
import { readFile } from "fs/promises";

describe("generateCircuitInputsWithDecomposedRegexesAndExternalInputs test suite", async () => {
  await init();
  const helloEml = await readFile("tests/fixtures/test.eml", "utf-8");

  test("Should create circuit inputs", async () => {
    const decomposedRegexes = [
      {
        parts: [
          {
            isPublic: true,
            regexDef: "Hi",
          },
          {
            isPublic: true,
            regexDef: "!",
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
    expect(inputs).toBeDefined();
  });

  test("Should create circuit inputs with external inputs", async () => {
    const decomposedRegexes = [
      {
        parts: [
          {
            isPublic: true,
            regexDef: "Hi",
          },
          {
            isPublic: true,
            regexDef: "!",
          },
        ],
        name: "hi",
        maxLength: 64,
        location: "body",
      },
    ];

    const externalInputs = [
      {
        name: "address",
        maxLength: 64,
        value: "tester@zkemail.com",
      },
    ];

    const params = {
      maxHeaderLength: 2816,
      maxBodyLength: 1024,
      ignoreBodyHashCheck: false,
      removeSoftLinesBreaks: true,
      // sha_precompute_selector
    };

    const inputs = await generateCircuitInputsWithDecomposedRegexesAndExternalInputs(
      helloEml,
      decomposedRegexes,
      externalInputs,
      params
    );
    expect(inputs).toBeDefined();
  });
});
