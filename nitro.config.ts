import { defineConfig } from "nitro";

export default defineConfig({
  serverDir: "./server",
  runtimeConfig: {
    analysisApiKey: "",
    analysisRepositories: "",
    analysisLocalRoots: "",
    analysisWebsiteHosts: "",
  },
});
