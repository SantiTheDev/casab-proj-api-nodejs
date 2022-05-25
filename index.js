const express = require('express')
const app = express()
const bodyparser = require('body-parser')

//body capture
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());

// import routes
const authRoutes = require('./routes/auth.js');

app.use(express.json());

// route middlewares
app.use('/api/user',authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`server running on: ${PORT}`)
})

