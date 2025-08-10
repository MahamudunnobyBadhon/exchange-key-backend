const { Server } = require("socket.io");
const { io: Client } = require("socket.io-client");
const CryptoManager = require("./CryptoManager");

const FRONTEND_PORT = 3001;
const PEER_PORT = 8000;

let crypto = new CryptoManager();
let feSocket = null;
let peerSocket = null;
let isSecure = false;

const feIo = new Server(FRONTEND_PORT, { cors: { origin: "http://localhost:3000" } });

feIo.on("connection", (socket) => {
    console.log("React UI connected.");
    feSocket = socket;

    socket.on("connect-to-peer", (peerAddress) => {
        console.log(`Connecting to peer at ${peerAddress}:${PEER_PORT}`);
        peerSocket = Client(`http://${peerAddress}:${PEER_PORT}`);

        // --- THIS IS THE FIX ---
        // When this client successfully connects to the other peer,
        // send the "Peer connected" status to our own UI.
        peerSocket.on("connect", () => {
            console.log("Successfully connected to peer as a client.");
            if(feSocket) feSocket.emit("status-update", "Peer connected.");
        });
        // --- END OF FIX ---

        setupPeerListeners();
    });
    
    socket.on("send-message", (message) => {
        if (!peerSocket) return;
        const type = isSecure ? "secure_msg" : "plaintext_msg";
        const payload = isSecure ? crypto.encryptMessage(message) : message;
        peerSocket.emit(type, payload);
    });
    socket.on("initiate-secure-session", () => {
        if (!peerSocket) return;
        const ecdhKeyBuffer = crypto.ecdh.getPublicKey();
        const signature = crypto.signData(ecdhKeyBuffer);
        const payload = {
            rsaKey: crypto.rsaKeyPair.publicKey,
            ecdhKey: ecdhKeyBuffer.toString('base64'),
            signature: signature.toString('base64')
        };
        peerSocket.emit("key-exchange-init", payload);
        feSocket.emit("status-update", "Key exchange initiated...");
    });
});

const beIo = new Server(PEER_PORT);
beIo.on("connection", (socket) => {
    console.log("Peer backend connected.");
    if (feSocket) feSocket.emit("status-update", "Peer connected.");
    peerSocket = socket;
    setupPeerListeners();
});

function setupPeerListeners() {
    if (!peerSocket) return;
    peerSocket.on("plaintext_msg", (message) => {
        if (feSocket) feSocket.emit("new-message", { sender: "Peer", text: message });
    });
    peerSocket.on("secure_msg", (message) => {
        const decrypted = crypto.decryptMessage(message);
        if (feSocket) feSocket.emit("new-message", { sender: "Peer (Encrypted)", text: decrypted });
    });
    peerSocket.on("key-exchange-init", (payload) => {
        const peerEcdhKeyBuffer = Buffer.from(payload.ecdhKey, 'base64');
        const signatureBuffer = Buffer.from(payload.signature, 'base64');
        crypto.peerRsaPublicKey = payload.rsaKey;
        if (crypto.verifySignature(peerEcdhKeyBuffer, signatureBuffer)) {
            feSocket.emit("status-update", "Signature valid. Responding...");
            crypto.peerEcdhPublicKey = peerEcdhKeyBuffer;
            crypto.generateSharedSecret();
            const ackEcdhKeyBuffer = crypto.ecdh.getPublicKey();
            const ackSignature = crypto.signData(ackEcdhKeyBuffer);
            const ackPayload = {
                rsaKey: crypto.rsaKeyPair.publicKey,
                ecdhKey: ackEcdhKeyBuffer.toString('base64'),
                signature: ackSignature.toString('base64')
            };
            peerSocket.emit("key-exchange-ack", ackPayload);
            isSecure = true;
            feSocket.emit("status-update", "Secure session established!");
        } else {
            feSocket.emit("status-update", "ERROR: Invalid signature from peer.");
        }
    });
    peerSocket.on("key-exchange-ack", (payload) => {
        const peerEcdhKeyBuffer = Buffer.from(payload.ecdhKey, 'base64');
        const signatureBuffer = Buffer.from(payload.signature, 'base64');
        crypto.peerRsaPublicKey = payload.rsaKey;
        if (crypto.verifySignature(peerEcdhKeyBuffer, signatureBuffer)) {
            crypto.peerEcdhPublicKey = peerEcdhKeyBuffer;
            crypto.generateSharedSecret();
            isSecure = true;
            feSocket.emit("status-update", "Secure session established!");
        } else {
            feSocket.emit("status-update", "ERROR: Invalid signature in ACK.");
        }
    });
    peerSocket.on("disconnect", () => {
        console.log("Peer disconnected.");
        peerSocket = null;
        if (feSocket) feSocket.emit('status-update', "Peer disconnected.");
    });
}
console.log(`Backend ready.\nUI Server on port ${FRONTEND_PORT}.\nPeer Server on port ${PEER_PORT}.`);