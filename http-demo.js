const { createServer } = require("http");
// createServer((req, res) => {
//   res.write("hello world");
// }).listen("9060");
console.log(123, createServer);
const server = createServer((req, res) => {
  res.write("hello world");
});
server.listen(8080);
