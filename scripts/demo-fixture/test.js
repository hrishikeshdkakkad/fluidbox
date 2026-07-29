const { greet } = require("./app.js");
const got = greet("Ada");
if (got !== "Hello, Ada!") {
  console.error(`FAIL greet("Ada") -> ${JSON.stringify(got)} (expected "Hello, Ada!")`);
  process.exit(1);
}
console.log("PASS 1/1 greet returns a personal greeting");
