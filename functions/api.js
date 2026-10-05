const serverless = require("serverless-http");
const app = require("../server");

const handler = serverless(app, {
    request: (req, event) => {
        // Handle raw string or base64 bodies sent by Netlify
        if (event.body) {
            let rawBody = event.body;
            if (event.isBase64Encoded) {
                rawBody = Buffer.from(event.body, "base64").toString("utf8");
            }
            try {
                req.body = JSON.parse(rawBody);
            } catch (e) {
                // If urlencoded or plain text, pass as string
                req.body = rawBody;
            }
        }
    }
});

module.exports.handler = async (event, context) => {
    return await handler(event, context);
};