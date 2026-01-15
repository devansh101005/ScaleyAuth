import express from "express"

const app=express()
const PORT = 3000

app.use(express.json())

app.use((err, req, res, next) => {
  res.status(400).json({
    message: err.message
  });
});



app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})