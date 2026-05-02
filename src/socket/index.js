const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");

let io;

const getToken = (socket) => {
  const authToken = socket.handshake.auth?.token;
  const queryToken = socket.handshake.query?.token;
  const header = socket.handshake.headers?.authorization;

  if (authToken) return authToken;
  if (queryToken) return queryToken;
  if (header?.startsWith("Bearer ")) return header.slice(7);

  return null;
};

const initSocket = (server) => {
  io = new Server(server, {
    cors: {
      origin: process.env.SOCKET_CORS_ORIGIN || "*",
      methods: ["GET", "POST"]
    }
  });

  io.use((socket, next) => {
    try {
      const token = getToken(socket);

      if (!token) {
        return next(new Error("Unauthorized"));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = String(decoded.id);
      next();
    } catch (err) {
      next(new Error("Unauthorized"));
    }
  });

  io.on("connection", (socket) => {
    // Each authenticated user gets an isolated private room.
    socket.join(socket.userId);

    socket.emit("connected", {
      userId: socket.userId
    });
  });

  return io;
};

const getIO = () => io;

const emitToUser = (userId, eventName, payload) => {
  if (!io || !userId) return;
  io.to(String(userId)).emit(eventName, payload);
};

module.exports = {
  emitToUser,
  getIO,
  initSocket
};
