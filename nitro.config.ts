import { defineConfig } from "nitro";

export default defineConfig({
  serverDir: "./server",
  runtimeConfig: {
    analysisApiKey: "",
    analysisWorkerSecret: "",
    analysisRepositories: "",
    analysisLocalRoots: "",
    analysisWebsiteHosts: "",
  },
});
