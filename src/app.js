require("dotenv").config();

const express = require("express");
const path = require("node:path");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const connectDB = require("./config/db");
require("./scheduler/scanScheduler");

const app = express();

app.set("trust proxy", 1);

if (process.env.NODE_ENV !== "test") {
  connectDB();
}

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "32kb" }));
app.use(morgan("dev"));

app.get("/tracker.js", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "tracker.js"));
});

app.use("/api/auth", require("./routes/auth"));
app.use("/api/dashboard", require("./routes/dashboardRoutes"));
app.use("/api/events", require("./routes/eventRoutes"));
app.use("/api/scans", require("./routes/scan"));
app.use("/api/websites", require("./routes/websiteRoutes"));
app.use("/api/users", require("./routes/users"));
app.use("/api/visualization", require("./routes/visualization"));

app.get("/", (req, res) => {
  res.send("API Running");
});

app.use((req, res) => {
  res.status(404).json({ msg: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ msg: "Server error" });
});

module.exports = app;
