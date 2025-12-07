const express = require("express");
const app = express();
const PORT = 3005;

let isUp = true;

// 正常健康
app.get("/health", (req, res) => {
  if (!isUp) {
    return res.status(500).send("ERROR");
  }
  res.status(200).send("OK");
});

// 切換狀態
app.get("/flip", (req, res) => {
  isUp = !isUp;
  res.json({ now: isUp ? "UP (200)" : "DOWN (500)" });
});

app.listen(PORT, () => {
  console.log(`Test API running: http://localhost:${PORT}/health`);
});