import "./style.css";
// import { setupNoirProver } from "./noirProver.ts";
import { setupCircomProver } from "./circomProver.ts";

document.querySelector<HTMLDivElement>("#app")!.innerHTML = `
  <div>
    <h1>ZK Email SDK Browser Test</h1>
    <div id="noir-prover" class="mb-5">
      <div className="flex mt-5">
        <button class="prove">Prove with Noir</button>
      </div>
    </div>
    <div id="circom-prover" class="mb-5">
      <div className="flex mt-5">
        <button class="prove">Prove with Circom</button>
      </div>
    </div>
  </div>
`;

// setupNoirProver(document.querySelector<HTMLElement>("#noir-prover")!);
setupCircomProver(document.querySelector<HTMLElement>("#circom-prover")!);
