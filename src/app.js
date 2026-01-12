import express from "express"

const app=express()
const PORT = 3000

app.use(express.json())


app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})