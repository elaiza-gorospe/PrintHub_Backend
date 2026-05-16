const express = require("express");

// Some deployment scanners expect the entrypoint itself to import and initialize Express.
const app = express();
void app;

require("../server");
