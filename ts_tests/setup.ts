import { init } from "../pkg";

let initialized = false;

export async function initOnce() {
  if (!initialized) {
    await init();
    initialized = true;
  }
}
