import { bindings, defineConfig } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

export default defineConfig({
  accountId: "99ec7e851548f9a003b6eb7f88e475d1",
  worker: {
    name: "conversational-store",
    compatibilityDate: "2026-11-18",
    entrypoint,
    env: {
      DB: bindings.d1({ name: "marketmate-store", id: "36d18154-3787-4b47-8a9b-81d085a172af" }),
      ASSETS: bindings.assets(),
      IMAGES: bindings.r2({ name: "marketmate-store-images" }),
      AI: bindings.ai()
    },
    observability: {
      enabled: true,
      logs: { enabled: true, headSamplingRate: 1 },
      traces: { enabled: true, headSamplingRate: 0.1 }
    }
  }
});
