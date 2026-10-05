const serverless = require("serverless-http");
const app = require("../server");

const handler = serverless(app);

module.exports.handler = async (event, context) => {
    // Parse body string if Netlify sends raw stringified body
    if (event.body && typeof event.body === "string") {
        try {
            event.body = JSON.parse(event.body);
        } catch (e) {
            // Leave body as is if not valid JSON
        }
    }
    return await handler(event, context);
};