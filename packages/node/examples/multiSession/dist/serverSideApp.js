"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const solid_client_authn_node_1 = require("@inrupt/solid-client-authn-node");
const cookie_session_1 = __importDefault(require("cookie-session"));
const express_1 = __importDefault(require("express"));
const clientApplicationName = "solid-client-authn-node multi session demo";
const app = (0, express_1.default)();
const PORT = 3001;
const DEFAULT_OIDC_ISSUER = "https://login.inrupt.com/";
const REDIRECT_URL = "http://localhost:3001/redirect";
app.use((0, cookie_session_1.default)({
    name: "session",
    keys: [
        "Required, but value not relevant for this demo - key1",
        "Required, but value not relevant for this demo - key2",
    ],
    maxAge: 24 * 60 * 60 * 1000,
}));
app.get("/", async (req, res, next) => {
    const sessionIds = await (0, solid_client_authn_node_1.getSessionIdFromStorageAll)();
    const sessions = await Promise.all(sessionIds.map(async (sessionId) => {
        return (0, solid_client_authn_node_1.getSessionFromStorage)(sessionId);
    }));
    const htmlSessions = `${sessions.reduce((sessionList, session) => {
        if (session === null || session === void 0 ? void 0 : session.info.isLoggedIn) {
            return `${sessionList}<li><strong>${session === null || session === void 0 ? void 0 : session.info.webId}</strong></li>`;
        }
        return `${sessionList}<li>Logging in process</li>`;
    }, "<ul>")}</ul>`;
    res.send(`<p>There are currently [${sessionIds.length}] visitors: ${htmlSessions}</p>`);
});
app.get("/login", async (req, res, next) => {
    const session = new solid_client_authn_node_1.Session();
    req.session.sessionId = session.info.sessionId;
    await session.login({
        redirectUrl: REDIRECT_URL,
        oidcIssuer: DEFAULT_OIDC_ISSUER,
        clientName: clientApplicationName,
        handleRedirect: (redirectUrl) => res.redirect(redirectUrl),
    });
    if (session.info.isLoggedIn) {
        res.send(`<p>Already logged in with WebID: <strong>[${session.info.webId}]</strong></p>`);
    }
});
app.get("/redirect", async (req, res) => {
    const session = await (0, solid_client_authn_node_1.getSessionFromStorage)(req.session.sessionId);
    if (session === undefined) {
        res
            .status(400)
            .send(`<p>No session stored for ID [${req.session.sessionId}]</p>`);
    }
    else {
        await session.handleIncomingRedirect(getRequestFullUrl(req));
        if (session.info.isLoggedIn) {
            res.send(`<p>Logged in as [<strong>${session.info.webId}</strong>] after redirect</p>`);
        }
        else {
            res.status(400).send(`<p>Not logged in after redirect</p>`);
        }
    }
    res.end();
});
app.get("/fetch", async (req, res, next) => {
    const session = await (0, solid_client_authn_node_1.getSessionFromStorage)(req.session.sessionId);
    if (!req.query.resource) {
        res
            .status(400)
            .send("<p>Expected a 'resource' query param, for example <strong>http://localhost:3001/fetch?resource=https://pod.inrupt.com/MY_USERNAME/</strong> to fetch the resource at the root of your Pod (which, by default, only <strong>you</strong> will have access to).</p>");
    }
    else {
        const { fetch } = session !== null && session !== void 0 ? session : new solid_client_authn_node_1.Session();
        res.send(`<pre>${(await (await fetch(req.query.resource)).text()).replace(/</g, "&lt;")}</pre>`);
    }
});
app.get("/logout", async (req, res, next) => {
    const session = await (0, solid_client_authn_node_1.getSessionFromStorage)(req.session.sessionId);
    if (session) {
        const { webId } = session.info;
        session.logout();
        res.send(`<p>Logged out of session with WebID [${webId}]</p>`);
    }
    else {
        res.status(400).send(`<p>No active session to log out</p>`);
    }
});
app.listen(PORT, async () => {
    console.log(`Listening on [${PORT}]...`);
});
function getRequestFullUrl(request) {
    return `${request.protocol}://${request.get("host")}${request.originalUrl}`;
}
//# sourceMappingURL=serverSideApp.js.map