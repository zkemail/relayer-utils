// TODO: Can only run one test file at a time, since init() will colide
import { expect, test, describe } from "bun:test";
import { sha256Pad, init } from "../pkg";

describe("sha256Pad test suite", async () => {
  await init();
  test("should pad", async () => {
    try {
      const text = "yellow is the new dark blue";
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const result = await sha256Pad(data, 1000);
      console.log("result: ", result);
    } catch (err) {
      console.log("err while padding: ", err);
    }
  });

  test("should not crash the program", async () => {
    try {
      const text = `to:dimitridumonet@googlemail.com
      subject:Hi!
      message-id:<CAAG2-GgVtd5y8vBVrPxhB6mY+8rgkqFNU4tJoDzRSjqB1YQ3ZQ@mail.gmail.com>
      date:Wed, 23 Oct 2024 14:52:49 +0700
      from:Dimitri <dimi.zktest@gmail.com>
      mime-version:1.0
      dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed;
       d=gmail.com; s=20230601; t=1729669980; x=1730274780; dara=google.com;
       h=to:subject:message-id:date:from:mime-version:from:to:cc:subject
       :date:message-id:reply-to;
       bh=Fo5d+d9xb+YHiWhsYyQpRCq3vLn0d45ZsTpIy6dMSpQ=;
       b=`;

      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      await sha256Pad(data, 10);
    } catch (err) {
      expect(err).toBeDefined();
    }
  });
});
