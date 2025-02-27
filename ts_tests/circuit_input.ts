// TODO: Can only run one test file at a time, since init() will colide
import { expect, test, describe } from "bun:test";
import { generateCircuitInputsWithDecomposedRegexesAndExternalInputs, init } from "../pkg";
import { readFile } from "fs/promises";

describe("generateCircuitInputsWithDecomposedRegexesAndExternalInputs test suite", async () => {
  await init();
  const helloEml = await readFile("tests/fixtures/test.eml", "utf-8");
  const binanceEml = await readFile("tests/fixtures/confidential/binance.eml", "utf-8");

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

  test("Should create circuit inputs with external inputs, binance", async () => {
    const decomposedRegexes = [
      {
        name: "emailRecipient",
        parts: [
          { regexDef: "(\r\n|^)to:", isPublic: false },
          { regexDef: "([^\r\n]+<)?", isPublic: false },
          {
            isPublic: true,
            regexDef: "[a-zA-Z0-9!#$%&\\*\\+-/=\\?\\^_`{\\|}~\\.]+@[a-zA-Z0-9_\\.-]+",
          },
          { regexDef: ">?\r\n", isPublic: false },
        ],
        location: "header",
        maxLength: 64,
      },
      {
        name: "senderDomain",
        parts: [
          { regexDef: "(\r\n|^)from:[^\r\n]*@", isPublic: false },
          { isPublic: true, regexDef: "[A-Za-z0-9][A-Za-z0-9\\.-]+\\.[A-Za-z]{2,}" },
          { regexDef: "[>\r\n]", isPublic: false },
        ],
        location: "header",
        maxLength: 64,
      },
      {
        name: "emailTimestamp",
        parts: [
          { regexDef: "(\r\n|^)dkim-signature:", isPublic: false },
          { regexDef: "([a-z]+=[^;]+; )+t=", isPublic: false },
          { isPublic: true, regexDef: "[0-9]+" },
          { regexDef: ";", isPublic: false },
        ],
        location: "header",
        maxLength: 64,
      },
      {
        name: "subject",
        parts: [
          { regexDef: "(\r\n|^)subject:", isPublic: false },
          { isPublic: true, regexDef: "[^\r\n]+" },
          { regexDef: "\r\n", isPublic: false },
        ],
        location: "header",
        maxLength: 128,
      },
    ];

    const externalInputs = [
      {
        name: "address",
        maxLength: 44,
        value: "0x0000",
      },
    ];

    const params = {
      maxHeaderLength: 1024,
      maxBodyLength: 0,
      ignoreBodyHashCheck: true,
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
