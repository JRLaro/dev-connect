const express = require("express");
const connectDB = require("./config/db");

//init express
const app = express();

//connect database
connectDB();

//init middleware
app.use(express.json({ extended: false }));

//testing - DELETE
app.get("/", (req, res) => res.send("API RUNNING"));

//define routes
app.use('/api/users', require('./routes/api/users'))
app.use('/api/profile', require('./routes/api/profile'))
app.use('/api/posts', require('./routes/api/posts'))
app.use('/api/auth', require('./routes/api/auth'))


//create port
const PORT = process.env.PORT || 7000;

app.listen(PORT, () => console.log(`Server started on port:${PORT}`));
