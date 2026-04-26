const express = require(`express`)
const app = express()
const fs = require(`fs`)
const path = require(`path`)
const bcrypt = require(`bcrypt`)
const key = fs.readFileSync(path.join(__dirname , `localhost.key`))
const cert = fs.readFileSync(path.join(__dirname , `localhost.crt`))
const https = require(`https`)
const httpsNeccecities = {key:key , cert:cert}
const { query, validationResult, body } = require('express-validator');

app.use(express.json());
const getFileData = () => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname,`data.json`), "utf8"));
  } catch {
    return [];
  }
};
const saveFileData = (data) => {
  fs.writeFileSync(path.join(__dirname,`data.json`), JSON.stringify(data, null, 2));
};


app.post("/register",[body('mail').isEmail().withMessage(`Please enter valid email`),
  body(`userName`).notEmpty().withMessage(`Username is required`),
  body(`password`).isLength({min:8}).withMessage(`Password too short`)], async(req,res)=>{
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const {userName,mail,password} = req.body
    
  const users = getFileData()
   try{
    if(users.find((u)=>u.userName===userName)){
        return res.status(404).send(`User already exists`)
    }
    if(users.find((u)=>u.mail===mail)){
        return res.status(404).send(`User already exists`)
    }
    const hashedPassword = await bcrypt.hash(password,10)
    const newUser = {
        userName:userName,
        password:hashedPassword,
        email:mail
    }
    users.push(newUser);
    saveFileData(users)
}catch(err){
    console.log(err);
    res.status(404).send(`Server Error`)
    return []
}
})

const server = https.createServer((httpsNeccecities), app)
server.listen(8080, (req,res)=>{
    console.log(`Server is spinning on port 3000`)
})