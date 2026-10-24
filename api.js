const serverless = require("serverless-http");
const app = require("../server.js"); // Если файл в папке functions
// Если файл в папке netlify/functions, то путь должен быть: require("../../server.js")

module.exports.handler = serverless(app);